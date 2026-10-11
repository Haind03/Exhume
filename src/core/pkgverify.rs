//! Package integrity: dpkg md5sums and `rpm -V` output, plus the scope of files worth hashing.

use super::paths::file_name;
use super::report::{Category, Finding, Severity};

/// `<md5>  <path relative to />` lines of /var/lib/dpkg/info/<pkg>.md5sums.
pub fn parse_md5sums(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let (h, p) = l.split_once(char::is_whitespace)?;
            let p = p.trim_start();
            (h.len() == 32 && h.bytes().all(|b| b.is_ascii_hexdigit()) && !p.is_empty()).then(
                || {
                    (
                        h.to_ascii_lowercase(),
                        format!("/{}", p.trim_start_matches('/')),
                    )
                },
            )
        })
        .collect()
}

/// Libraries whose tampering is a classic backdoor (Ebury, PAM backdoors, libc hooks, sshd).
const CRITICAL_LIB_PREFIXES: &[&str] = &[
    "libc.so",
    "libc-",
    "ld-linux",
    "libpam",
    "libkeyutils",
    "libselinux",
    "libaudit",
    "libsystemd",
    "libcrypt",
    "libnss_",
    "libprocps",
    "libproc2",
    "libutil",
    "libdl",
    "libpthread",
    "libresolv",
    "libssl",
    "libcrypto",
    "liblzma",
    "libz.so",
    "libwrap",
];

fn is_bin_dir(p: &str) -> bool {
    [
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/libexec/openssh/",
        "/usr/lib/openssh/",
    ]
    .iter()
    .any(|d| p.starts_with(d) && !p[d.len()..].contains('/'))
}

fn is_pam_module(p: &str) -> bool {
    p.contains("/security/pam_") && p.ends_with(".so")
}

fn is_critical_lib(p: &str) -> bool {
    (p.starts_with("/lib") || p.starts_with("/usr/lib"))
        && CRITICAL_LIB_PREFIXES
            .iter()
            .any(|l| file_name(p).starts_with(l))
}

/// Default scope: executables in bin dirs, PAM modules and core libraries. `deep` hashes everything.
pub fn in_scope(p: &str, deep: bool) -> bool {
    deep || is_bin_dir(p) || is_pam_module(p) || is_critical_lib(p)
}

pub fn mismatch_severity(p: &str) -> Severity {
    if is_bin_dir(p) || is_pam_module(p) || is_critical_lib(p) {
        Severity::Critical
    } else if p.starts_with("/usr/lib")
        || p.starts_with("/lib")
        || p.ends_with(".so")
        || p.contains(".so.")
    {
        Severity::High
    } else if p.starts_with("/usr/share/") {
        Severity::Low
    } else {
        Severity::Medium
    }
}

pub fn mismatch_finding(manager: &str, pkg: &str, path: &str, detail: &str) -> Finding {
    Finding::new(mismatch_severity(path), Category::Integrity, "Package file fails integrity verification")
        .path(path)
        .detail(format!("{manager} package: {pkg}"))
        .detail(detail.to_string())
        .detail("a modified system binary or library is how trojanised ls/ps/sshd and PAM/libkeyutils backdoors persist")
        .mitre(&["T1554", "T1036.005"])
}

/// One line of `rpm -V` output: (flags, is_config, path). `missing` lines have flags "missing".
pub fn parse_rpm_verify(text: &str) -> Vec<(String, bool, String)> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim_end();
            if let Some(rest) = l.strip_prefix("missing") {
                let rest = rest.trim_start();
                let (cfg, path) = match rest.split_once(' ') {
                    Some((a, p)) if a.len() == 1 && p.trim_start().starts_with('/') => {
                        (a == "c", p.trim_start())
                    }
                    _ => (false, rest),
                };
                return path
                    .starts_with('/')
                    .then(|| ("missing".into(), cfg, path.to_string()));
            }
            let flags = l.get(..9)?;
            if !flags.bytes().all(|b| b"SM5DLUGTP.?c".contains(&b)) {
                return None;
            }
            let rest = l[9..].trim_start();
            let (cfg, path) = match rest.split_once(' ') {
                Some((a, p)) if a.len() == 1 && "cdglr".contains(a) => (a == "c", p.trim_start()),
                _ => (false, rest),
            };
            path.starts_with('/')
                .then(|| (flags.to_string(), cfg, path.to_string()))
        })
        .collect()
}

/// rpm verify lines that indicate content tampering (digest changed on a non-config file).
pub fn rpm_tampered(flags: &str, is_config: bool) -> bool {
    !is_config && flags.as_bytes().get(2) == Some(&b'5')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5sums() {
        let t = "d41d8cd98f00b204e9800998ecf8427e  usr/bin/ls\nbad line\n0123456789abcdef0123456789ABCDEF  usr/share/doc/x/copyright\n";
        let v = parse_md5sums(t);
        assert_eq!(v.len(), 2);
        assert_eq!(
            v[0],
            (
                "d41d8cd98f00b204e9800998ecf8427e".into(),
                "/usr/bin/ls".into()
            )
        );
        assert_eq!(v[1].0, "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn scope_and_severity() {
        assert!(in_scope("/usr/bin/ls", false));
        assert!(in_scope(
            "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
            false
        ));
        assert!(in_scope("/lib/x86_64-linux-gnu/libkeyutils.so.1.9", false));
        assert!(!in_scope("/usr/share/doc/a", false));
        assert!(!in_scope("/usr/bin/sub/x", false));
        assert!(in_scope("/usr/share/doc/a", true));
        assert_eq!(mismatch_severity("/usr/sbin/sshd"), Severity::Critical);
        assert_eq!(
            mismatch_severity("/usr/lib/x86_64-linux-gnu/libfoo.so.1"),
            Severity::High
        );
        assert_eq!(mismatch_severity("/usr/share/x/y.png"), Severity::Low);
    }

    #[test]
    fn rpm() {
        let t = "S.5....T.  c /etc/ssh/sshd_config\n..5....T.    /usr/bin/ps\nmissing     /usr/share/doc/x\nmissing   c /etc/y\n.M.......    /usr/bin/su\nerror: x\n";
        let v = parse_rpm_verify(t);
        assert_eq!(v.len(), 5);
        assert_eq!(
            v[0],
            ("S.5....T.".into(), true, "/etc/ssh/sshd_config".into())
        );
        assert_eq!(v[1].2, "/usr/bin/ps");
        assert!(rpm_tampered(&v[1].0, v[1].1));
        assert!(!rpm_tampered(&v[0].0, v[0].1));
        assert_eq!(v[2].0, "missing");
        assert_eq!(v[3], ("missing".into(), true, "/etc/y".into()));
        assert!(!rpm_tampered(&v[4].0, v[4].1));
    }
}
