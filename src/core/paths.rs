//! Path classification shared by every rule set.

/// Last path component.
pub fn file_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Strip the kernel's " (deleted)" suffix from a /proc link target.
pub fn strip_deleted(p: &str) -> (&str, bool) {
    match p.strip_suffix(" (deleted)") {
        Some(s) => (s, true),
        None => (p, false),
    }
}

/// `/memfd:name (deleted)` -> `Some("name")`.
pub fn memfd_name(p: &str) -> Option<&str> {
    let (p, _) = strip_deleted(p);
    p.strip_prefix("/memfd:")
        .or_else(|| p.strip_prefix("memfd:"))
}

/// World-writable staging directories malware drops into.
pub const STAGING_DIRS: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/shm/",
    "/dev/mqueue/",
    "/var/run/shm/",
];

pub fn in_staging_dir(p: &str) -> bool {
    STAGING_DIRS.iter().any(|d| p.starts_with(d))
}

/// Hidden directories that legitimately hold executables.
const BENIGN_HIDDEN: &[&str] = &[
    ".cargo",
    ".rustup",
    ".local",
    ".vscode-server",
    ".vscode",
    ".cursor-server",
    ".npm",
    ".nvm",
    ".pyenv",
    ".rbenv",
    ".sdkman",
    ".deno",
    ".bun",
    ".dotnet",
    ".m2",
    ".gradle",
    ".cache",
    ".config",
    ".mozilla",
    ".steam",
    ".var",
    ".git",
    ".venv",
    ".conda",
    ".tox",
    ".nix-profile",
    ".jenkins",
    ".asdf",
    ".jetbrains",
    ".windsurf-server",
];

/// Hidden directory that is not one of the usual tool caches.
pub fn unusual_hidden_dir(p: &str) -> Option<&str> {
    let parent = p.rsplit_once('/').map(|(d, _)| d)?;
    parent
        .split('/')
        .filter(|c| c.len() > 1 && c.starts_with('.') && *c != "..")
        .find(|c| !BENIGN_HIDDEN.contains(c))
}

/// System locations where executables and libraries normally live.
pub const SYSTEM_PREFIXES: &[&str] = &[
    "/usr/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib32/",
    "/lib64/",
    "/libx32/",
    "/opt/",
    "/snap/",
    "/nix/store/",
    "/var/lib/snapd/",
    "/var/lib/flatpak/",
    "/gnu/store/",
    "/etc/alternatives/",
];

pub fn in_system_dir(p: &str) -> bool {
    SYSTEM_PREFIXES.iter().any(|d| p.starts_with(d))
}

/// Container runtimes expose other mount namespaces' files under these paths.
pub fn in_container_rootfs(p: &str) -> bool {
    p.starts_with("/var/lib/docker/")
        || p.starts_with("/var/lib/containerd/")
        || p.starts_with("/run/containerd/")
        || p.starts_with("/var/lib/containers/")
        || p.starts_with("/run/k3s/")
}

/// Why a path is a suspicious place for code to run from, if it is.
pub fn suspicious_location(p: &str) -> Option<String> {
    if p.starts_with("/dev/shm/") || p.starts_with("/run/shm/") || p.starts_with("/dev/mqueue/") {
        return Some("shared-memory filesystem (RAM only, common for fileless droppers)".into());
    }
    if in_staging_dir(p) {
        return Some("world-writable temp directory".into());
    }
    if let Some(h) = unusual_hidden_dir(p) {
        return Some(format!("hidden directory '{h}'"));
    }
    if p.starts_with("/dev/") {
        return Some("/dev is not a place for executables".into());
    }
    None
}

/// Merged-/usr aliases: dpkg may record `/bin/ls` while the kernel reports `/usr/bin/ls`.
pub fn usr_aliases(p: &str) -> Vec<String> {
    let mut v = vec![p.to_string()];
    for d in ["/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/"] {
        if let Some(rest) = p.strip_prefix(d) {
            v.push(format!("/usr{d}{rest}"));
        }
        if let Some(rest) = p.strip_prefix(&format!("/usr{d}")) {
            v.push(format!("{d}{rest}"));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deleted_and_memfd() {
        assert_eq!(strip_deleted("/tmp/x (deleted)"), ("/tmp/x", true));
        assert_eq!(strip_deleted("/usr/bin/ls"), ("/usr/bin/ls", false));
        assert_eq!(memfd_name("/memfd:payload (deleted)"), Some("payload"));
        assert_eq!(memfd_name("/memfd: (deleted)"), Some(""));
        assert_eq!(memfd_name("/usr/bin/ls"), None);
    }

    #[test]
    fn locations() {
        assert!(suspicious_location("/dev/shm/x")
            .unwrap()
            .contains("shared-memory"));
        assert!(suspicious_location("/tmp/a/b").is_some());
        assert!(suspicious_location("/var/tmp/b").is_some());
        assert!(suspicious_location("/root/.x/kworker")
            .unwrap()
            .contains(".x"));
        assert!(suspicious_location("/home/u/.cargo/bin/rg").is_none());
        assert!(suspicious_location("/usr/bin/ls").is_none());
        assert!(
            suspicious_location("/home/u/.hidden_file").is_none(),
            "hidden file in normal dir is not a hidden dir"
        );
        assert_eq!(unusual_hidden_dir("/a/.b/c"), Some(".b"));
    }

    #[test]
    fn aliases() {
        let a = usr_aliases("/bin/ls");
        assert!(a.contains(&"/usr/bin/ls".to_string()));
        let b = usr_aliases("/usr/lib/x86_64-linux-gnu/libc.so.6");
        assert!(b.contains(&"/lib/x86_64-linux-gnu/libc.so.6".to_string()));
        assert!(in_system_dir("/usr/sbin/sshd"));
        assert!(!in_system_dir("/home/u/a.out"));
    }
}
