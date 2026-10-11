//! Rootkit cross-views: PIDs alive but missing from /proc, kernel modules missing from one of
//! /proc/modules, /sys/module and /proc/kallsyms, kernel taint flags and loaded eBPF programs.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use super::report::{Category, Finding, Severity};

/// PIDs that answer kill(pid, 0) but are absent from every /proc listing (processes and their threads).
pub fn crossview_pids(listed: &HashSet<u32>, alive: &[u32]) -> Vec<u32> {
    alive
        .iter()
        .copied()
        .filter(|p| !listed.contains(p))
        .collect()
}

pub fn hidden_pid_finding(pid: u32, name: Option<&str>, exe: Option<&str>) -> Finding {
    let mut f = Finding::new(
        Severity::Critical,
        Category::Rootkit,
        "Process hidden from /proc listing",
    )
    .detail(format!(
        "pid {pid} answers kill(pid, 0) but is missing from readdir(/proc) on two passes"
    ))
    .detail("getdents/proc hooking by a userland or kernel rootkit")
    .mitre(&["T1014", "T1564"]);
    f.pid = Some(pid);
    f.process = name.map(String::from).or(Some("?".into()));
    if let Some(e) = exe {
        f = f.path(e);
    }
    f
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KModule {
    pub name: String,
    pub size: u64,
    pub state: String,
    /// Taint letters from the trailing "(OE)" column.
    pub taint: String,
}

/// Parse /proc/modules.
pub fn parse_proc_modules(text: &str) -> Vec<KModule> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 5 {
                return None;
            }
            let taint = f
                .iter()
                .skip(6)
                .find(|x| x.starts_with('('))
                .map(|x| x.trim_matches(|c| c == '(' || c == ')').to_string())
                .unwrap_or_default();
            Some(KModule {
                name: f[0].to_string(),
                size: f[1].parse().unwrap_or(0),
                state: f[4].to_string(),
                taint,
            })
        })
        .collect()
}

/// Module names that own symbols in /proc/kallsyms (`... [name]`), minus kernel pseudo-modules.
pub fn kallsyms_modules(text: &str) -> BTreeSet<String> {
    let mut s = BTreeSet::new();
    for l in text.lines() {
        if let Some(open) = l.rfind('[') {
            if let Some(name) = l[open + 1..].strip_suffix(']') {
                let name = name.trim();
                if !name.is_empty()
                    && name != "bpf"
                    && !name.starts_with("__builtin")
                    && !name.contains("ftrace")
                {
                    s.insert(name.to_string());
                }
            }
        }
    }
    s
}

/// Names of public LKM rootkits seen in the wild and in red-team kits.
const ROOTKIT_MODULES: &[&str] = &[
    "diamorphine",
    "reptile",
    "reptile_module",
    "suterusu",
    "adore",
    "adore_ng",
    "knark",
    "kovid",
    "khook",
    "nuk3gh0st",
    "puszek",
    "brokepkg",
    "singularity",
    "caraxes",
    "rkduck",
    "enyelkm",
    "phalanx",
    "azazel",
    "jynx",
    "vlany",
    "kbeast",
    "sutekh",
    "lilyofthevalley",
    "masquerade",
    "bds_lkm",
    "drovorub",
    "kinsing_rk",
    "spectre_rk",
    "umbra",
    "basic_hiding",
];

/// Out-of-tree modules that are common and expected (DKMS drivers, hypervisors, filesystems).
const COMMON_OOT: &[&str] = &[
    "nvidia",
    "nvidia_drm",
    "nvidia_modeset",
    "nvidia_uvm",
    "nvidia_peermem",
    "vboxdrv",
    "vboxnetflt",
    "vboxnetadp",
    "vboxpci",
    "vboxguest",
    "vboxsf",
    "vboxvideo",
    "vmmon",
    "vmnet",
    "vmw_vmci",
    "zfs",
    "spl",
    "zcommon",
    "znvpair",
    "zavl",
    "icp",
    "zlua",
    "zunicode",
    "zzstd",
    "v4l2loopback",
    "evdi",
    "wireguard",
    "falco",
    "sysdig_probe",
    "scap",
    "xpadneo",
    "hid_xpadneo",
    "acpi_call",
    "tp_smapi",
    "bbswitch",
    "openrazer",
    "razerkbd",
    "it87",
    "nct6687",
    "r8125",
    "r8168",
    "8821cu",
    "88x2bu",
    "8812au",
    "rtl88x2bu",
    "ddcci",
    "ddcci_backlight",
    "amdgpu",
    "kvdo",
    "uds",
    "lttng_tracer",
    "crowdstrike",
    "falcon_lsm_serviceable",
    "mdatp",
    "sentinelone",
    "cs_ipc",
    "veeamsnap",
    "blksnap",
    "drbd",
    "lustre",
    "gpfs",
    "mmfs26",
    "vmw_balloon",
    "wazuh",
];

pub fn module_findings(
    proc_modules: &[KModule],
    sysfs_loadable: &BTreeSet<String>,
    kallsyms: Option<&BTreeSet<String>>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let listed: BTreeSet<&str> = proc_modules.iter().map(|m| m.name.as_str()).collect();

    if let Some(ks) = kallsyms {
        for m in ks.iter().filter(|m| !listed.contains(m.as_str())) {
            out.push(
                Finding::new(Severity::Critical, Category::Rootkit, "Kernel module hidden from /proc/modules")
                    .path(format!("module {m}"))
                    .detail("module owns symbols in /proc/kallsyms but is unlinked from the module list (list_del hiding)")
                    .mitre(&["T1014", "T1547.006"]),
            );
        }
    }
    for m in sysfs_loadable
        .iter()
        .filter(|m| !listed.contains(m.as_str()))
    {
        out.push(
            Finding::new(
                Severity::High,
                Category::Rootkit,
                "Kernel module in /sys/module but not in /proc/modules",
            )
            .path(format!("module {m}"))
            .detail("loadable module with an initstate in sysfs that the module list does not show")
            .mitre(&["T1014", "T1547.006"]),
        );
    }
    for m in proc_modules {
        let lname = m.name.to_ascii_lowercase();
        if !sysfs_loadable.is_empty() && !sysfs_loadable.contains(&m.name) && m.state == "Live" {
            out.push(
                Finding::new(
                    Severity::Medium,
                    Category::Rootkit,
                    "Kernel module missing from /sys/module",
                )
                .path(format!("module {}", m.name))
                .detail("sysfs kobject removed: a hiding technique used by LKM rootkits")
                .mitre(&["T1014"]),
            );
        }
        if ROOTKIT_MODULES
            .iter()
            .any(|r| lname == *r || lname.starts_with(&format!("{r}_")))
        {
            out.push(
                Finding::new(
                    Severity::Critical,
                    Category::Rootkit,
                    "Known LKM rootkit module name loaded",
                )
                .path(format!("module {}", m.name))
                .mitre(&["T1014", "T1547.006"]),
            );
        }
        let oot = m.taint.contains('O');
        let unsigned = m.taint.contains('E');
        if (oot || unsigned) && !COMMON_OOT.contains(&lname.as_str()) {
            let mut flags = Vec::new();
            if oot {
                flags.push("out-of-tree");
            }
            if unsigned {
                flags.push("unsigned");
            }
            out.push(
                Finding::new(
                    if unsigned {
                        Severity::Medium
                    } else {
                        Severity::Low
                    },
                    Category::Rootkit,
                    "Uncommon out-of-tree or unsigned kernel module",
                )
                .path(format!("module {}", m.name))
                .detail(format!("taint ({}): {}", m.taint, flags.join(", ")))
                .detail(format!(
                    "size {} bytes; verify it belongs to an installed driver package",
                    m.size
                ))
                .mitre(&["T1547.006", "T1014"]),
            );
        }
    }
    out
}

/// Kernel taint bits (Documentation/admin-guide/tainted-kernels.rst).
pub const TAINT_BITS: &[(u32, char, &str)] = &[
    (0, 'P', "proprietary module loaded"),
    (1, 'F', "module force-loaded"),
    (2, 'S', "SMP kernel on unsupported hardware"),
    (3, 'R', "module force-unloaded"),
    (4, 'M', "machine check exception"),
    (5, 'B', "bad page referenced"),
    (6, 'U', "taint requested by userspace"),
    (7, 'D', "kernel died recently (OOPS or BUG)"),
    (8, 'A', "ACPI table overridden"),
    (9, 'W', "kernel issued a warning"),
    (10, 'C', "staging driver loaded"),
    (11, 'I', "platform firmware bug workaround"),
    (12, 'O', "out-of-tree module loaded"),
    (13, 'E', "unsigned module loaded"),
    (14, 'L', "soft lockup occurred"),
    (15, 'K', "kernel live patched"),
    (16, 'X', "auxiliary taint (distro defined)"),
    (17, 'T', "built with struct randomization plugin"),
    (18, 'N', "in-kernel test run"),
    (
        19,
        'J',
        "userspace used a mutating debug operation in fwctl",
    ),
];

pub fn decode_taint(v: u64) -> Vec<(char, &'static str)> {
    TAINT_BITS
        .iter()
        .filter(|(b, _, _)| v & (1u64 << b) != 0)
        .map(|(_, c, d)| (*c, *d))
        .collect()
}

pub fn taint_finding(v: u64) -> Option<Finding> {
    if v == 0 {
        return None;
    }
    let bits = decode_taint(v);
    let letters: String = bits.iter().map(|b| b.0).collect();
    let sev = if letters.contains('F') || letters.contains('R') {
        Severity::Medium
    } else if letters.contains('E') || letters.contains('U') {
        Severity::Low
    } else {
        Severity::Info
    };
    let mut f = Finding::new(
        sev,
        Category::Rootkit,
        format!("Kernel is tainted ({letters})"),
    )
    .path("/proc/sys/kernel/tainted")
    .detail(format!("value {v}"));
    for (c, d) in bits {
        f = f.detail(format!("{c}: {d}"));
    }
    Some(f.mitre(&["T1547.006"]))
}

#[derive(Debug, Clone, Default)]
pub struct BpfProg {
    pub id: u32,
    pub prog_type: u32,
    pub name: String,
    pub tag: String,
    pub uid: u32,
    /// (pid, comm) of processes holding an fd to the program.
    pub holders: Vec<(u32, String)>,
}

pub fn bpf_type_name(t: u32) -> &'static str {
    match t {
        1 => "socket_filter",
        2 => "kprobe",
        3 => "sched_cls",
        4 => "sched_act",
        5 => "tracepoint",
        6 => "xdp",
        7 => "perf_event",
        8 => "cgroup_skb",
        9 => "cgroup_sock",
        10..=12 => "lwt",
        13 => "sock_ops",
        14 => "sk_skb",
        15 => "cgroup_device",
        16 => "sk_msg",
        17 => "raw_tracepoint",
        18 => "cgroup_sock_addr",
        19 => "lwt_seg6local",
        20 => "lirc_mode2",
        21 => "sk_reuseport",
        22 => "flow_dissector",
        23 => "cgroup_sysctl",
        24 => "raw_tracepoint_writable",
        25 => "cgroup_sockopt",
        26 => "tracing",
        27 => "struct_ops",
        28 => "ext",
        29 => "lsm",
        30 => "sk_lookup",
        31 => "syscall",
        32 => "netfilter",
        _ => "unknown",
    }
}

/// Types that can observe or rewrite syscalls and kernel functions (eBPF rootkits live here).
fn tracing_type(t: u32) -> bool {
    matches!(t, 2 | 5 | 7 | 17 | 24 | 26 | 29 | 31)
}

/// Types that see raw packets (magic-packet backdoors such as BPFDoor-style triggers).
fn packet_type(t: u32) -> bool {
    matches!(t, 1 | 3 | 4 | 6 | 21 | 30 | 32)
}

/// Agents and tools that load eBPF programs as part of their job.
const BPF_LOADERS: &[&str] = &[
    "systemd",
    "systemd-journal",
    "systemd-logind",
    "systemd-network",
    "systemd-resolve",
    "systemd-oomd",
    "bpftrace",
    "bpftool",
    "falco",
    "tetragon",
    "cilium-agent",
    "tracee",
    "sysdig",
    "pixie",
    "datadog-agent",
    "system-probe",
    "parca-agent",
    "pyroscope",
    "auditbeat",
    "osqueryd",
    "falcon-sensor",
    "elastic-endpoint",
    "elastic-agent",
    "mdatp",
    "wdavdaemon",
    "s1-agent",
    "sentinelone",
    "kube-proxy",
    "calico-node",
    "flanneld",
    "dockerd",
    "containerd",
    "crio",
    "kubelet",
    "kepler",
    "opensnitchd",
    "bcc",
    "execsnoop",
    "opensnoop",
    "tcplife",
    "inspektor-gadget",
    "coroot-node-agent",
    "beyla",
    "netdata",
    "ebpf.plugin",
    "node-agent",
    "wazuh-agentd",
    "snapd",
];

pub fn bpf_findings(progs: &[BpfProg]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut by_type: BTreeMap<&str, usize> = BTreeMap::new();
    for p in progs {
        *by_type.entry(bpf_type_name(p.prog_type)).or_default() += 1;
        let known = p
            .holders
            .iter()
            .any(|(_, c)| BPF_LOADERS.iter().any(|l| c == l || c.starts_with(l)));
        let systemd_name = p.name.starts_with("sd_") || p.name.starts_with("sd-");
        if known || systemd_name {
            continue;
        }
        let (sev, why) = if tracing_type(p.prog_type) {
            (Severity::Medium, "can hook syscalls/kernel functions; eBPF rootkits use this to hide files, processes and steal data")
        } else if packet_type(p.prog_type) {
            (Severity::Low, "inspects raw packets; magic-packet backdoors use socket filters and XDP/TC programs")
        } else {
            continue;
        };
        let holders = if p.holders.is_empty() {
            "no process holds it (pinned or attached by a loader that exited)".to_string()
        } else {
            p.holders
                .iter()
                .map(|(pid, c)| format!("{c}[{pid}]"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push(
            Finding::new(
                sev,
                Category::Rootkit,
                format!(
                    "eBPF {} program loaded by an unrecognised owner",
                    bpf_type_name(p.prog_type)
                ),
            )
            .path(format!(
                "bpf prog id {} name '{}' tag {}",
                p.id, p.name, p.tag
            ))
            .detail(why)
            .detail(format!("holders: {holders}"))
            .detail(format!("loaded by uid {}", p.uid))
            .mitre(if packet_type(p.prog_type) {
                &["T1205.002", "T1014"]
            } else {
                &["T1014"]
            }),
        );
    }
    if !progs.is_empty() {
        let summary = by_type
            .iter()
            .map(|(t, n)| format!("{t}: {n}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(
            Finding::new(
                Severity::Info,
                Category::Rootkit,
                format!("{} eBPF programs loaded", progs.len()),
            )
            .detail(summary),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_crossview() {
        let listed: HashSet<u32> = [1, 2, 3, 10].into_iter().collect();
        assert_eq!(crossview_pids(&listed, &[1, 2, 3, 10, 666]), vec![666]);
        assert!(crossview_pids(&listed, &[1, 2]).is_empty());
        let f = hidden_pid_finding(666, Some("evil"), None);
        assert_eq!(f.severity, Severity::Critical);
    }

    const MODS: &str = "\
diamorphine 16384 0 - Live 0xffffffffc0a00000 (OE)
vboxdrv 696320 2 vboxnetadp,vboxnetflt, Live 0x0000000000000000 (OE)
ext4 1048576 1 - Live 0xffffffffc0b00000
mystery 20480 0 - Live 0xffffffffc0c00000 (OE)
";

    #[test]
    fn proc_modules_parse() {
        let m = parse_proc_modules(MODS);
        assert_eq!(m.len(), 4);
        assert_eq!(m[0].name, "diamorphine");
        assert_eq!(m[0].taint, "OE");
        assert_eq!(m[1].taint, "OE");
        assert_eq!(m[2].taint, "");
        assert_eq!(m[2].state, "Live");
    }

    #[test]
    fn module_crossview() {
        let m = parse_proc_modules(MODS);
        let sys: BTreeSet<String> = ["diamorphine", "vboxdrv", "ext4", "mystery", "ghost_sys"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let ks = kallsyms_modules("ffffffffc0a00010 t hacked_kill\t[diamorphine]\nffffffffc0d00000 t x\t[hidden_one]\nffffffffc0e00000 t bpf_prog_1\t[bpf]\nffff t y [__builtin__ftrace]\n");
        assert_eq!(ks.len(), 2);
        let f = module_findings(&m, &sys, Some(&ks));
        let t: Vec<_> = f
            .iter()
            .map(|f| {
                (
                    f.severity,
                    f.title.as_str(),
                    f.path.clone().unwrap_or_default(),
                )
            })
            .collect();
        assert!(t.iter().any(|x| x.0 == Severity::Critical
            && x.1.contains("hidden from /proc/modules")
            && x.2.contains("hidden_one")));
        assert!(t
            .iter()
            .any(|x| x.0 == Severity::High && x.2.contains("ghost_sys")));
        assert!(t.iter().any(|x| x.1.contains("Known LKM rootkit")));
        assert!(t
            .iter()
            .any(|x| x.1.contains("Uncommon out-of-tree") && x.2.contains("mystery")));
        assert!(!t.iter().any(|x| x.2.contains("vboxdrv")), "{t:?}");
    }

    #[test]
    fn taint() {
        assert!(taint_finding(0).is_none());
        let f = taint_finding((1 << 12) | (1 << 13)).unwrap();
        assert_eq!(f.title, "Kernel is tainted (OE)");
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(taint_finding(1 << 1).unwrap().severity, Severity::Medium);
        assert_eq!(taint_finding(1 << 9).unwrap().severity, Severity::Info);
        assert_eq!(decode_taint(1).len(), 1);
    }

    #[test]
    fn bpf() {
        let progs = vec![
            BpfProg {
                id: 1,
                prog_type: 15,
                name: "sd_devices".into(),
                ..Default::default()
            },
            BpfProg {
                id: 2,
                prog_type: 2,
                name: "hook_getdents".into(),
                ..Default::default()
            },
            BpfProg {
                id: 3,
                prog_type: 26,
                name: "x".into(),
                holders: vec![(10, "tetragon".into())],
                ..Default::default()
            },
            BpfProg {
                id: 4,
                prog_type: 6,
                name: "xdp_trigger".into(),
                holders: vec![(11, "updater".into())],
                ..Default::default()
            },
        ];
        let f = bpf_findings(&progs);
        assert!(f
            .iter()
            .any(|f| f.severity == Severity::Medium && f.title.contains("kprobe")));
        assert!(f
            .iter()
            .any(|f| f.severity == Severity::Low && f.title.contains("xdp")));
        assert!(!f.iter().any(|f| f.title.contains("tracing")));
        assert!(f
            .iter()
            .any(|f| f.severity == Severity::Info && f.title.starts_with("4 eBPF")));
    }
}
