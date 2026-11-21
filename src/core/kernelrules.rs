//! Kernel hook and kernel log analysis: ftrace callbacks (tracefs `enabled_functions`), kprobes
//! (`kprobe_events`, debugfs `kprobes/list`) and the kernel ring buffer (`/dev/kmsg`).
//!
//! Many current LKM rootkits hook syscalls and `/proc` readers through ftrace instead of patching
//! the syscall table. Each ftrace callback is listed in `enabled_functions` with the symbol of the
//! callback, which carries a `[module]` suffix when it lives in a module, so a hook owned by a
//! module that is missing from `/proc/modules` is a hidden module caught in the act.

use std::collections::{BTreeMap, BTreeSet};

use super::report::{Category, Finding, Severity};
use super::timefmt;

/// Kernel functions a rootkit hooks to hide files, processes, sockets and modules or to gain
/// control of process creation. Syscall entry points (`__x64_sys_*`, `__arm64_sys_*`, ...) are
/// matched separately.
const SENSITIVE: &[&str] = &[
    "filldir",
    "filldir64",
    "iterate_dir",
    "vfs_readdir",
    "proc_pid_readdir",
    "proc_root_readdir",
    "tcp4_seq_show",
    "tcp6_seq_show",
    "udp4_seq_show",
    "udp6_seq_show",
    "packet_rcv",
    "tpacket_rcv",
    "packet_rcv_spkt",
    "find_task_by_vpid",
    "find_get_pid",
    "kallsyms_lookup_name",
    "kallsyms_on_each_symbol",
    "audit_log_start",
    "audit_log_end",
    "do_sys_open",
    "do_sys_openat2",
    "vfs_read",
    "vfs_statx",
    "load_module",
    "do_init_module",
    "free_module",
    "commit_creds",
    "prepare_creds",
    "account_process_tick",
    "copy_creds",
    "seq_read",
    "inet_ioctl",
    "ip_rcv",
    "nf_hook_slow",
];

/// Is this a syscall entry point or one of the functions rootkits hook?
pub fn sensitive_function(func: &str) -> bool {
    let f = func.split('+').next().unwrap_or(func);
    f.contains("_sys_") || f.starts_with("sys_") || f.starts_with("ksys_") || SENSITIVE.contains(&f)
}

/// One function with ftrace callbacks attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtraceHook {
    pub function: String,
    /// Modules named in the callback symbols (`fh_ftrace_thunk+0x0/0x20 [rk]` -> `rk`).
    pub owners: Vec<String>,
    /// The line as the kernel printed it.
    pub line: String,
}

/// Parses tracefs `enabled_functions`. Indented continuation lines (`direct-->`, extra ops) are
/// folded into the function above.
pub fn parse_enabled_functions(text: &str) -> Vec<FtraceHook> {
    let mut out: Vec<FtraceHook> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let owners = bracket_modules(line);
        if line.starts_with(char::is_whitespace) {
            if let Some(last) = out.last_mut() {
                for o in owners {
                    if !last.owners.contains(&o) {
                        last.owners.push(o);
                    }
                }
                last.line.push_str(" | ");
                last.line.push_str(line.trim());
            }
            continue;
        }
        let function = line
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        out.push(FtraceHook {
            function,
            owners,
            line: line.trim().to_string(),
        });
    }
    out
}

/// `[name]` tokens that look like module names (the kernel's `%pS` module suffix).
fn bracket_modules(line: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut rest = line;
    while let Some(i) = rest.find('[') {
        rest = &rest[i + 1..];
        let Some(j) = rest.find(']') else { break };
        let name = &rest[..j];
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            && !name.chars().all(|c| c.is_ascii_digit())
            && name != "FTRACE"
            && name != "DISABLED"
            && name != "OPTIMIZED"
            && name != "GONE"
            && !v.iter().any(|x| x == name)
        {
            v.push(name.to_string());
        }
        rest = &rest[j + 1..];
    }
    v
}

/// Live kernel patching modules hook functions through ftrace by design.
fn livepatch_module(name: &str, livepatches: &BTreeSet<String>) -> bool {
    livepatches.contains(name)
        || name.starts_with("livepatch_")
        || name.starts_with("kpatch_")
        || name.starts_with("klp_")
}

/// Findings for ftrace hooks owned by kernel modules. `loaded` is the module list from
/// /proc/modules, `livepatches` the entries of /sys/kernel/livepatch.
pub fn ftrace_findings(
    hooks: &[FtraceHook],
    loaded: &BTreeSet<String>,
    livepatches: &BTreeSet<String>,
) -> Vec<Finding> {
    // module -> hooked functions
    let mut by_owner: BTreeMap<&str, Vec<&FtraceHook>> = BTreeMap::new();
    for h in hooks {
        for o in &h.owners {
            by_owner.entry(o.as_str()).or_default().push(h);
        }
    }
    let mut out = Vec::new();
    for (owner, hs) in by_owner {
        let hidden = !loaded.contains(owner);
        let lp = livepatch_module(owner, livepatches);
        let sensitive: Vec<&str> = hs
            .iter()
            .map(|h| h.function.as_str())
            .filter(|f| sensitive_function(f))
            .collect();
        let (sev, title) = if hidden && !lp {
            (
                Severity::Critical,
                format!("ftrace hooks owned by a module missing from /proc/modules: {owner}"),
            )
        } else if lp {
            (
                Severity::Info,
                format!("Live patch module {owner} redirects kernel functions"),
            )
        } else if !sensitive.is_empty() {
            (
                Severity::High,
                format!("Kernel module {owner} hooks syscalls or hiding-related functions through ftrace"),
            )
        } else {
            (
                Severity::Medium,
                format!("Kernel module {owner} hooks kernel functions through ftrace"),
            )
        };
        let mut f = Finding::new(sev, Category::Rootkit, title)
            .path(format!("module {owner}"))
            .detail(format!("{} hooked function(s)", hs.len()));
        if !sensitive.is_empty() {
            f = f.detail(format!(
                "sensitive: {}",
                sensitive
                    .iter()
                    .take(12)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        for h in hs.iter().take(6) {
            f = f.detail(h.line.clone());
        }
        if hidden && !lp {
            f = f.detail("the module is not listed in /proc/modules: hidden or unloaded with its hooks left behind");
        }
        out.push(f.mitre(&["T1014", "T1547.006"]));
    }
    out
}

/// One kprobe from debugfs `kprobes/list` or tracefs `kprobe_events`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kprobe {
    /// `k` (kprobe), `r` (kretprobe), `p`/`f` for tracefs events.
    pub kind: String,
    pub symbol: String,
    /// Module named on the line, if any.
    pub module: Option<String>,
    pub line: String,
}

/// Parses debugfs `kprobes/list`: `ffffffff81234560  k  __x64_sys_kill+0x0    [FTRACE]`.
pub fn parse_kprobes_list(text: &str) -> Vec<Kprobe> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let _addr = it.next()?;
            let kind = it.next()?.to_string();
            let symbol = it.next()?.to_string();
            Some(Kprobe {
                kind,
                module: bracket_modules(l).into_iter().next(),
                symbol,
                line: l.trim().to_string(),
            })
        })
        .collect()
}

/// Parses tracefs `kprobe_events`: `p:kprobes/myprobe do_sys_open dfd=%ax` or
/// `r:myretprobe vfs_read $retval`.
pub fn parse_kprobe_events(text: &str) -> Vec<Kprobe> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let head = it.next()?;
            let kind = head.split(':').next()?.trim_end_matches(char::is_numeric);
            let target = it.next()?;
            // MOD:SYM targets name the module explicitly.
            let (module, symbol) = match target.split_once(':') {
                Some((m, s)) => (Some(m.to_string()), s.to_string()),
                None => (None, target.to_string()),
            };
            Some(Kprobe {
                kind: kind.to_string(),
                symbol,
                module,
                line: l.trim().to_string(),
            })
        })
        .collect()
}

/// Kprobes on sensitive functions. eBPF agents (Falco, Tetragon, Tracee, Datadog ...) use kprobes
/// legitimately, so `bpf_kprobes` (kprobe-type eBPF programs loaded) lowers the severity.
pub fn kprobe_findings(probes: &[Kprobe], source: &str, bpf_kprobes: bool) -> Vec<Finding> {
    let sensitive: Vec<&Kprobe> = probes
        .iter()
        .filter(|p| sensitive_function(&p.symbol))
        .collect();
    if sensitive.is_empty() {
        return Vec::new();
    }
    let sev = if bpf_kprobes {
        Severity::Low
    } else {
        Severity::Medium
    };
    let mut f = Finding::new(
        sev,
        Category::Rootkit,
        format!(
            "Kernel probes on syscalls or hiding-related functions ({})",
            sensitive.len()
        ),
    )
    .path(source.to_string());
    for p in sensitive.iter().take(10) {
        f = f.detail(p.line.clone());
    }
    f = f.detail(if bpf_kprobes {
        "kprobe eBPF programs are loaded, which usually explains these probes (security or observability agent)"
    } else {
        "no kprobe eBPF program is loaded to explain them: check which module or tool registered them"
    });
    vec![f.mitre(&["T1014"])]
}

/// One record of /dev/kmsg: `pri,seq,usec,flags;message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsgRecord {
    /// Syslog facility: 0 = kernel. Records written to /dev/kmsg from user space carry the
    /// user facility (1) unless they say otherwise, and never facility 0.
    pub facility: u32,
    pub seq: u64,
    /// Microseconds since boot.
    pub usec: u64,
    pub msg: String,
}

pub fn parse_kmsg_record(rec: &str) -> Option<KmsgRecord> {
    let (head, msg) = rec.split_once(';')?;
    let mut it = head.split(',');
    let pri: u32 = it.next()?.parse().ok()?;
    let seq = it.next()?.parse().ok()?;
    let usec = it.next()?.parse().ok()?;
    // Continuation lines (" SUBSYSTEM=...") carry dictionary data only.
    let msg = msg.lines().next().unwrap_or_default().to_string();
    Some(KmsgRecord {
        facility: pri >> 3,
        seq,
        usec,
        msg,
    })
}

/// Privileged programs whose crashes in the kernel log point to local exploitation attempts.
const PRIVILEGED: &[&str] = &[
    "sudo",
    "sudoedit",
    "pkexec",
    "su",
    "passwd",
    "chfn",
    "chsh",
    "newgrp",
    "gpasswd",
    "mount",
    "umount",
    "fusermount",
    "fusermount3",
    "polkitd",
    "polkit-agent-he",
    "sshd",
    "dbus-daemon-lau",
    "snap-confine",
    "exim4",
    "Xorg",
    "at",
    "crontab",
    "unix_chkpwd",
    "ping",
];

struct Hit {
    sev: Severity,
    title: String,
    key: String,
    mitre: &'static [&'static str],
    note: Option<&'static str>,
}

/// `name[pid]: rest` or `name: rest` at the start of a message.
fn subject(msg: &str) -> Option<(&str, &str)> {
    let (a, rest) = msg.split_once(": ")?;
    let name = a.split('[').next().unwrap_or(a);
    (!name.is_empty() && !name.contains(' ')).then_some((name, rest))
}

fn quoted(s: &str, n: usize) -> Option<&str> {
    s.split('\'').nth(n * 2 + 1)
}

fn classify(msg: &str, modules_now: &BTreeSet<String>) -> Option<Hit> {
    let gone = |m: &str| !modules_now.contains(m);
    if msg.contains("module verification failed: signature and/or required key missing") {
        let m = subject(msg)?.0;
        return Some(if gone(m) {
            Hit {
                sev: Severity::High,
                title: format!("Unsigned kernel module {m} was loaded and is no longer listed"),
                key: m.to_string(),
                mitre: &["T1547.006", "T1014"],
                note: Some("not in /proc/modules now: unloaded, or hiding itself"),
            }
        } else {
            Hit {
                sev: Severity::Medium,
                title: format!("Unsigned kernel module loaded: {m}"),
                key: m.to_string(),
                mitre: &["T1547.006"],
                note: Some("DKMS drivers (VirtualBox, NVIDIA, ZFS ...) also trigger this on kernels that enforce signing"),
            }
        });
    }
    if msg.ends_with("loading out-of-tree module taints kernel.") {
        let m = subject(msg)?.0;
        return Some(Hit {
            sev: if gone(m) {
                Severity::High
            } else {
                Severity::Low
            },
            title: if gone(m) {
                format!("Out-of-tree kernel module {m} was loaded and is no longer listed")
            } else {
                format!("Out-of-tree kernel module loaded: {m}")
            },
            key: m.to_string(),
            mitre: &["T1547.006"],
            note: gone(m).then_some("not in /proc/modules now: unloaded, or hiding itself"),
        });
    }
    if msg.contains(": module license '") && msg.contains("taints kernel") {
        let m = subject(msg)?.0;
        let lic = quoted(msg, 0).unwrap_or("?");
        return Some(Hit {
            sev: if gone(m) {
                Severity::High
            } else {
                Severity::Low
            },
            title: format!("Kernel module {m} with license '{lic}' tainted the kernel"),
            key: m.to_string(),
            mitre: &["T1547.006"],
            note: gone(m).then_some("not in /proc/modules now: unloaded, or hiding itself"),
        });
    }
    if msg.contains(": Unknown symbol kallsyms_lookup_name")
        || msg.contains(": Unknown symbol sys_call_table")
    {
        let m = subject(msg)?.0;
        return Some(Hit {
            sev: Severity::Medium,
            title: format!("Kernel module {m} failed to resolve a symbol rootkits rely on"),
            key: m.to_string(),
            mitre: &["T1014"],
            note: Some("kallsyms_lookup_name/sys_call_table are not exported on current kernels; LKM rootkits ask for them"),
        });
    }
    if msg.contains("is installing a program with bpf_probe_write_user helper") {
        let p = msg.split(" is installing").next().unwrap_or(msg);
        return Some(Hit {
            sev: Severity::High,
            title: format!("eBPF program able to overwrite user memory loaded by {p}"),
            key: p.to_string(),
            mitre: &["T1014", "T1055"],
            note: Some("bpf_probe_write_user is how eBPF rootkits rewrite syscall results"),
        });
    }
    if msg.contains("with NULL argv: empty string added") {
        let prog = quoted(msg, 1).unwrap_or("?");
        return Some(Hit {
            sev: Severity::High,
            title: format!("Program executed with an empty argv: {prog}"),
            key: prog.to_string(),
            mitre: &["T1068"],
            note: Some("argc == 0 execution is the PwnKit (CVE-2021-4034) exploitation primitive"),
        });
    }
    if msg.starts_with("Lockdown: ") && msg.contains("is restricted") {
        let what = msg.splitn(3, ": ").nth(2).unwrap_or(msg);
        let what = what.split(" is restricted").next().unwrap_or(what);
        return Some(Hit {
            sev: Severity::Medium,
            title: format!("Kernel lockdown blocked: {what}"),
            key: what.to_string(),
            mitre: &["T1014", "T1547.006"],
            note: Some("something tried an operation that lockdown forbids (unsigned module, /dev/mem, kprobes ...)"),
        });
    }
    if msg.starts_with("ptrace attach of ") && msg.contains("was attempted by") {
        let by = msg
            .split("was attempted by ")
            .nth(1)
            .and_then(|b| b.split('"').nth(1))
            .unwrap_or("?");
        return Some(Hit {
            sev: Severity::Medium,
            title: format!("ptrace attach refused by Yama, attempted by {by}"),
            key: msg
                .split("was attempted by")
                .next()
                .unwrap_or(msg)
                .to_string(),
            mitre: &["T1055.008"],
            note: None,
        });
    }
    if msg.contains("Kernel memory overwrite attempt detected")
        || msg.contains("Kernel memory exposure attempt detected")
    {
        return Some(Hit {
            sev: Severity::High,
            title: "Hardened usercopy stopped a kernel memory overwrite or exposure".into(),
            key: "usercopy".into(),
            mitre: &["T1068"],
            note: None,
        });
    }
    if msg.contains(" started with executable stack") {
        let p = quoted(msg, 0).unwrap_or("?");
        return Some(Hit {
            sev: Severity::Low,
            title: format!("Process started with an executable stack: {p}"),
            key: p.to_string(),
            mitre: &["T1620"],
            note: Some("common for shellcode loaders; also old toolchains"),
        });
    }
    let crash = msg.contains("]: segfault at ")
        || (msg.starts_with("traps: ") && msg.contains("general protection"));
    if crash {
        let m = msg.strip_prefix("traps: ").unwrap_or(msg);
        let name = m.split('[').next().unwrap_or(m);
        if PRIVILEGED.contains(&name) {
            return Some(Hit {
                sev: Severity::Medium,
                title: format!("Privileged program {name} crashed (possible exploitation attempt)"),
                key: name.to_string(),
                mitre: &["T1068"],
                note: None,
            });
        }
    }
    None
}

/// Findings from kernel log records. `boot` is the boot time (epoch seconds) for timestamps,
/// `since` drops records older than that epoch time.
pub fn kmsg_findings(
    records: &[KmsgRecord],
    modules_now: &BTreeSet<String>,
    boot: u64,
    since: Option<u64>,
) -> Vec<Finding> {
    // (title, key) -> (hit, count, first record, last time)
    let mut agg: BTreeMap<(String, String), (Hit, usize, String, u64)> = BTreeMap::new();
    for r in records {
        // Only the kernel's own messages: user space can write anything to /dev/kmsg.
        if r.facility != 0 {
            continue;
        }
        let t = boot + r.usec / 1_000_000;
        if since.is_some_and(|s| t < s) {
            continue;
        }
        let Some(h) = classify(&r.msg, modules_now) else {
            continue;
        };
        let k = (h.title.clone(), h.key.clone());
        let e = agg.entry(k).or_insert((h, 0, r.msg.clone(), t));
        e.1 += 1;
        e.3 = t;
    }
    agg.into_values()
        .map(|(h, n, first, last)| {
            let mut f = Finding::new(h.sev, Category::Rootkit, h.title)
                .path("/dev/kmsg")
                .detail(first);
            if n > 1 {
                f = f.detail(format!("{n} times, last at {}", timefmt::iso8601(last)));
            } else {
                f = f.detail(format!("at {}", timefmt::iso8601(last)));
            }
            if let Some(note) = h.note {
                f = f.detail(note);
            }
            f.mitre(h.mitre)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENABLED: &str = "\
__x64_sys_getdents64 (1) R I  \ttramp: 0xffffffffc0a01000 (fh_ftrace_thunk+0x0/0x20 [diamorphine]) ->ftrace_ops_assist_func+0x0/0xf0
__x64_sys_kill (1) R I  \ttramp: 0xffffffffc0a01000 (fh_ftrace_thunk+0x0/0x20 [diamorphine]) ->ftrace_ops_assist_func+0x0/0xf0
tcp4_seq_show (1) R I  \ttramp: 0xffffffffc0a02000 (fh_ftrace_thunk+0x0/0x20 [diamorphine]) ->ftrace_ops_assist_func+0x0/0xf0
schedule (1) R   \ttramp: 0xffffffffc0a03000 (klp_ftrace_handler+0x0/0x100) ->ftrace_ops_assist_func+0x0/0xf0
	 [livepatch_fix1]
do_exit (1) R I  \ttramp: 0xffffffffc0b00000 (probe_cb+0x0/0x40 [vendor_av]) ->ftrace_ops_assist_func+0x0/0xf0
security_file_open (1) R   D   \tdirect-->bpf_trampoline_6442511234+0x0/0x80
";

    fn set(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_ftrace_owners() {
        let h = parse_enabled_functions(ENABLED);
        assert_eq!(h.len(), 6);
        assert_eq!(h[0].function, "__x64_sys_getdents64");
        assert_eq!(h[0].owners, vec!["diamorphine"]);
        assert_eq!(h[3].owners, vec!["livepatch_fix1"]);
        assert!(h[5].owners.is_empty());
    }

    #[test]
    fn hidden_owner_is_critical() {
        let h = parse_enabled_functions(ENABLED);
        let f = ftrace_findings(&h, &set(&["vendor_av"]), &BTreeSet::new());
        let rk = f.iter().find(|x| x.title.contains("diamorphine")).unwrap();
        assert_eq!(rk.severity, Severity::Critical);
        assert!(rk.details.iter().any(|d| d.contains("__x64_sys_kill")));
        let av = f.iter().find(|x| x.title.contains("vendor_av")).unwrap();
        assert_eq!(av.severity, Severity::Medium);
        let lp = f
            .iter()
            .find(|x| x.title.contains("livepatch_fix1"))
            .unwrap();
        assert_eq!(lp.severity, Severity::Info);
        assert_eq!(f.len(), 3, "the BPF trampoline has no module owner");
    }

    #[test]
    fn loaded_owner_hooking_syscalls_is_high() {
        let h = parse_enabled_functions(ENABLED);
        let f = ftrace_findings(&h, &set(&["diamorphine", "vendor_av"]), &BTreeSet::new());
        let rk = f.iter().find(|x| x.title.contains("diamorphine")).unwrap();
        assert_eq!(rk.severity, Severity::High);
    }

    #[test]
    fn kprobes() {
        let l = parse_kprobes_list(
            "ffffffff8112a2b0  k  __x64_sys_kill+0x0    [FTRACE]\nffffffffc0412000  k  my_func+0x4  [mymod]\nffffffff81300000  r  vfs_write+0x0\n",
        );
        assert_eq!(l.len(), 3);
        assert_eq!(l[1].module.as_deref(), Some("mymod"));
        assert!(l[0].module.is_none());
        let f = kprobe_findings(&l, "/sys/kernel/debug/kprobes/list", false);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].title.contains("(1)"));
        assert_eq!(kprobe_findings(&l, "x", true)[0].severity, Severity::Low);
        let e = parse_kprobe_events("p:kprobes/hide filldir64 a=%di\nr2:ret ext4:ext4_file_open\n");
        assert_eq!(e[0].symbol, "filldir64");
        assert_eq!(e[1].kind, "r");
        assert_eq!(e[1].module.as_deref(), Some("ext4"));
        assert!(sensitive_function("filldir64+0x10"));
        assert!(sensitive_function("__arm64_sys_openat"));
        assert!(!sensitive_function("ext4_file_open"));
    }

    fn rec(seq: u64, s: &str) -> KmsgRecord {
        parse_kmsg_record(&format!("4,{seq},{},-;{s}\n SUBSYSTEM=x", seq * 1_000_000)).unwrap()
    }

    #[test]
    fn kmsg_indicators() {
        let recs = vec![
            rec(1, "rk: loading out-of-tree module taints kernel."),
            rec(2, "rk: module verification failed: signature and/or required key missing - tainting kernel"),
            rec(3, "vboxdrv: module verification failed: signature and/or required key missing - tainting kernel"),
            rec(4, "process 'pkexec' launched '/usr/bin/pkexec' with NULL argv: empty string added"),
            rec(5, "sudo[4242]: segfault at 0 ip 000055d0 sp 00007ffc error 4 in sudo[55d0+1000]"),
            rec(6, "sudo[4243]: segfault at 0 ip 000055d0 sp 00007ffc error 4 in sudo[55d0+1000]"),
            rec(7, "firefox[999]: segfault at 0 ip 0 sp 0 error 4"),
            rec(8, "exp[77] is installing a program with bpf_probe_write_user helper that may corrupt user memory!"),
            rec(9, "Lockdown: insmod: unsigned module loading is restricted; see man kernel_lockdown.7"),
            rec(10, "ptrace attach of \"/usr/sbin/sshd\"[812] was attempted by \"/tmp/x\"[900]"),
            rec(11, "rk2: Unknown symbol kallsyms_lookup_name (err -2)"),
            rec(12, "random: crng init done"),
        ];
        let f = kmsg_findings(&recs, &set(&["vboxdrv"]), 1_700_000_000, None);
        let get = |t: &str| {
            f.iter()
                .find(|x| x.title.contains(t))
                .unwrap_or_else(|| panic!("{t}: {f:#?}"))
        };
        assert_eq!(
            get("Unsigned kernel module rk was loaded").severity,
            Severity::High
        );
        assert_eq!(
            get("Unsigned kernel module loaded: vboxdrv").severity,
            Severity::Medium
        );
        assert_eq!(get("Out-of-tree kernel module rk").severity, Severity::High);
        assert_eq!(get("empty argv").severity, Severity::High);
        let s = get("Privileged program sudo crashed");
        assert!(s.details.iter().any(|d| d.starts_with("2 times")));
        assert!(!f.iter().any(|x| x.title.contains("firefox")));
        assert_eq!(get("overwrite user memory").severity, Severity::High);
        assert!(get("lockdown blocked: unsigned module loading").severity == Severity::Medium);
        assert!(get("ptrace attach refused").title.ends_with("by /tmp/x"));
        assert_eq!(get("failed to resolve").severity, Severity::Medium);
        assert_eq!(f.len(), 9);
        // --lookback drops old records
        // A forged record written from user space (facility user) is ignored.
        let forged =
            parse_kmsg_record("12,99,1,-;rk3: loading out-of-tree module taints kernel.").unwrap();
        assert_eq!(forged.facility, 1);
        assert!(kmsg_findings(&[forged], &BTreeSet::new(), 0, None).is_empty());
        let late = kmsg_findings(&recs, &BTreeSet::new(), 1_700_000_000, Some(1_700_000_011));
        assert_eq!(late.len(), 1);
    }

    #[test]
    fn kmsg_record_parse() {
        let r =
            parse_kmsg_record("6,339,5140900,-;NET: Registered protocol family 10\n SUBSYSTEM=net")
                .unwrap();
        assert_eq!((r.seq, r.usec), (339, 5_140_900));
        assert_eq!(r.msg, "NET: Registered protocol family 10");
        assert!(parse_kmsg_record("garbage").is_none());
    }
}
