//! Code-injection indicators: dynamic-linker hijacking (LD_PRELOAD, LD_AUDIT, /etc/ld.so.preload)
//! and ptrace attachment (TracerPid).

use super::paths::{file_name, in_system_dir, suspicious_location};
use super::report::{Category, Finding, Severity};
use super::ProcInfo;

/// Preload libraries shipped by well-known packages.
const BENIGN_PRELOADS: &[&str] = &[
    "libgtk3-nocsd.so",
    "libfakeroot",
    "libeatmydata.so",
    "libfaketime",
    "libjemalloc.so",
    "libtcmalloc",
    "libmimalloc",
    "libsnapd-glib",
    "libvglfaker",
    "libdlfaker",
    "libgamemodeauto.so",
    "libnvidia-",
    "libtsocks",
    "libproxychains",
    "libasan.so",
    "libstdbuf.so",
    "libumockdev-preload",
    "libtrash.so",
    "libsandbox.so",
    "libvtpaint",
    "libmangohud",
];

pub fn benign_preload(lib: &str) -> bool {
    let n = file_name(lib);
    BENIGN_PRELOADS.iter().any(|b| n.starts_with(b))
}

/// Split an LD_PRELOAD value (space or colon separated).
pub fn split_preload(v: &str) -> Vec<&str> {
    v.split([' ', ':'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

/// Lines of /etc/ld.so.preload that name libraries (comments stripped).
pub fn parse_ld_so_preload(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .flat_map(|l| l.split_whitespace())
        .map(String::from)
        .collect()
}

fn lib_severity(lib: &str) -> (Severity, Option<String>) {
    if let Some(why) = suspicious_location(lib) {
        return (Severity::Critical, Some(why));
    }
    if benign_preload(lib) && (in_system_dir(lib) || !lib.contains('/')) {
        return (Severity::Low, Some("known preload library".into()));
    }
    if !in_system_dir(lib) && lib.contains('/') {
        return (
            Severity::High,
            Some("library outside system directories".into()),
        );
    }
    (Severity::High, None)
}

/// LD_PRELOAD / LD_AUDIT / LD_LIBRARY_PATH in a process's initial environment.
pub fn env_findings(p: &ProcInfo) -> Vec<Finding> {
    let mut out = Vec::new();
    for (k, v) in &p.ld_env {
        match k.as_str() {
            "LD_PRELOAD" | "LD_AUDIT" => {
                let libs = split_preload(v);
                let (mut sev, mut why) = (Severity::Info, None);
                for l in &libs {
                    let (s, w) = lib_severity(l);
                    if s > sev {
                        sev = s;
                        why = w;
                    }
                }
                if libs.is_empty() {
                    continue;
                }
                let mut f = Finding::new(
                    sev,
                    Category::Injection,
                    format!("{k} set in process environment"),
                )
                .proc(p.pid, p.name())
                .detail(format!("{k}={v}"))
                .mitre(&["T1574.006"]);
                if let Some(w) = why {
                    f = f.detail(w);
                }
                out.push(f);
            }
            "LD_LIBRARY_PATH" => {
                let bad: Vec<&str> = v
                    .split(':')
                    .filter(|d| suspicious_location(&format!("{d}/x")).is_some())
                    .collect();
                if !bad.is_empty() {
                    out.push(
                        Finding::new(
                            Severity::Medium,
                            Category::Injection,
                            "LD_LIBRARY_PATH points into a suspicious directory",
                        )
                        .proc(p.pid, p.name())
                        .detail(format!("LD_LIBRARY_PATH={v}"))
                        .mitre(&["T1574.006"]),
                    );
                }
            }
            _ => {}
        }
    }
    out
}

/// /etc/ld.so.preload is empty or absent on nearly every system; userland rootkits live there.
pub fn ld_so_preload_findings(
    path: &str,
    text: &str,
    lib_exists: &dyn Fn(&str) -> bool,
) -> Vec<Finding> {
    let libs = parse_ld_so_preload(text);
    if libs.is_empty() {
        return Vec::new();
    }
    let mut sev = Severity::High;
    let mut f = Finding::new(
        sev,
        Category::Injection,
        "System-wide preload configured in /etc/ld.so.preload",
    )
    .path(path)
    .mitre(&["T1574.006", "T1014"]);
    for l in &libs {
        let (s, why) = lib_severity(l);
        sev = sev.max(s);
        let exists = lib_exists(l);
        f = f.detail(format!(
            "{l}{}{}",
            why.map(|w| format!(" ({w})")).unwrap_or_default(),
            if exists {
                ""
            } else {
                " [file not visible: hidden or removed]"
            }
        ));
        if !exists {
            sev = Severity::Critical;
        }
    }
    f.severity = sev;
    f = f.detail(
        "every dynamically linked program loads these libraries; Exhume is static and unaffected",
    );
    vec![f]
}

/// Debuggers and tracers that legitimately attach with ptrace.
const TRACERS: &[&str] = &[
    "gdb",
    "strace",
    "ltrace",
    "lldb",
    "lldb-server",
    "gdbserver",
    "rr",
    "perf",
    "valgrind",
    "frida-server",
    "dlv",
    "ptrace",
    "systemtap",
    "crash",
    "pstack",
    "eu-stack",
    "criu",
    "proot",
    "code",
    "py-spy",
];

/// A traced process (TracerPid != 0). `tracer` is the tracing process name if known.
/// Processes that handle passwords, keys or authentication tokens in clear text.
const SECRET_HOLDERS: &[&str] = &[
    "sshd",
    "sshd-session",
    "sshd-auth",
    "sudo",
    "su",
    "login",
    "passwd",
    "chpasswd",
    "ssh",
    "ssh-agent",
    "gpg-agent",
    "gnome-keyring-d",
    "polkitd",
    "polkit-agent-he",
    "pkexec",
    "kinit",
    "vault",
    "keepassxc",
    "1password",
    "openvpn",
];

pub fn tracer_finding(p: &ProcInfo, tracer: Option<&str>) -> Option<Finding> {
    if p.tracer_pid == 0 {
        return None;
    }
    let known = tracer.is_some_and(|t| TRACERS.contains(&t));
    let secret = SECRET_HOLDERS.contains(&p.comm.as_str());
    let (sev, title, why, mitre): (_, _, _, &[&str]) = if secret {
        (
            Severity::Critical,
            "Authentication process is being ptrace-attached (credential capture)",
            "tracing sshd/sudo/passwd reads passwords and keys as they are typed; strace -p on sshd is a classic credential stealer",
            &["T1056", "T1055.008", "T1003"],
        )
    } else if known {
        (
            Severity::Low,
            "Process is being ptrace-attached",
            "tracer is a known debugger",
            &["T1055.008"],
        )
    } else {
        (
            Severity::High,
            "Process is being ptrace-attached",
            "ptrace is used for injection, credential theft from memory, and anti-debugging",
            &["T1055.008"],
        )
    };
    Some(
        Finding::new(sev, Category::Injection, title)
            .proc(p.pid, p.name())
            .detail(format!(
                "TracerPid {} ({})",
                p.tracer_pid,
                tracer.unwrap_or("unknown")
            ))
            .detail(why)
            .mitre(mitre),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(env: &[(&str, &str)]) -> ProcInfo {
        ProcInfo {
            pid: 9,
            comm: "x".into(),
            ld_env: env
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn preload_env() {
        let f = env_findings(&p(&[("LD_PRELOAD", "/dev/shm/.l/libx.so")]));
        assert_eq!(f[0].severity, Severity::Critical);
        let f = env_findings(&p(&[(
            "LD_PRELOAD",
            "/usr/lib/x86_64-linux-gnu/libjemalloc.so.2",
        )]));
        assert_eq!(f[0].severity, Severity::Low);
        let f = env_findings(&p(&[("LD_PRELOAD", "/home/u/hook.so")]));
        assert_eq!(f[0].severity, Severity::High);
        assert!(env_findings(&p(&[("LD_PRELOAD", "")])).is_empty());
        assert_eq!(
            env_findings(&p(&[("LD_LIBRARY_PATH", "/opt/x/lib:/tmp/.x")]))[0].severity,
            Severity::Medium
        );
        assert!(env_findings(&p(&[("LD_LIBRARY_PATH", "/opt/x/lib")])).is_empty());
    }

    #[test]
    fn ld_so_preload() {
        assert!(
            ld_so_preload_findings("/etc/ld.so.preload", "# nothing\n\n", &|_| true).is_empty()
        );
        let f = ld_so_preload_findings(
            "/etc/ld.so.preload",
            "/usr/local/lib/libprocesshider.so\n",
            &|_| true,
        );
        assert_eq!(f[0].severity, Severity::High);
        let f = ld_so_preload_findings("/etc/ld.so.preload", "/lib/libhide.so # x\n", &|_| false);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(
            parse_ld_so_preload("a.so b.so\n#c.so\n"),
            vec!["a.so", "b.so"]
        );
    }

    #[test]
    fn tracer() {
        let mut x = p(&[]);
        assert!(tracer_finding(&x, None).is_none());
        x.tracer_pid = 55;
        assert_eq!(
            tracer_finding(&x, Some("gdb")).unwrap().severity,
            Severity::Low
        );
        assert_eq!(
            tracer_finding(&x, Some("kthreadd")).unwrap().severity,
            Severity::High
        );
        let mut sshd = ProcInfo {
            pid: 7,
            comm: "sshd".into(),
            tracer_pid: 99,
            ..Default::default()
        };
        assert_eq!(
            tracer_finding(&sshd, Some("strace")).unwrap().severity,
            Severity::Critical
        );
        sshd.comm = "sudo".into();
        assert!(tracer_finding(&sshd, None)
            .unwrap()
            .title
            .contains("credential capture"));
    }

    #[test]
    fn split() {
        assert_eq!(
            split_preload("a.so:b.so c.so"),
            vec!["a.so", "b.so", "c.so"]
        );
    }
}
