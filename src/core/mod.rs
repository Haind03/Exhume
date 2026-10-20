//! Platform-independent analysis. Everything here works on plain data collected by `crate::linux`,
//! so the detection logic is unit-tested without touching a live host.

pub mod html;
pub mod injectrules;
pub mod memrules;
pub mod netrules;
pub mod paths;
pub mod persistext;
pub mod persistrules;
pub mod pkgverify;
pub mod procrules;
pub mod report;
pub mod resources;
pub mod rootkit;
pub mod timefmt;
pub mod webshell;

/// Snapshot of one process, read from /proc/<pid>.
#[derive(Debug, Clone, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    /// /proc/<pid>/comm (truncated to 15 bytes by the kernel).
    pub comm: String,
    /// argv, NUL-split.
    pub argv: Vec<String>,
    /// Raw /proc/<pid>/exe link target, including a " (deleted)" suffix. None = unreadable or kernel thread.
    pub exe: Option<String>,
    /// For a deleted executable: does a file exist at the original path again (package upgrade)?
    pub exe_replaced: bool,
    /// PF_KTHREAD from /proc/<pid>/stat.
    pub kthread: bool,
    pub tracer_pid: u32,
    /// Targets of fds 0, 1 and 2.
    pub stdio: [Option<String>; 3],
    /// Inodes of every socket the process holds.
    pub sockets: Vec<u64>,
    /// Dynamic-linker variables from the initial environment (LD_PRELOAD, LD_AUDIT, LD_LIBRARY_PATH).
    pub ld_env: Vec<(String, String)>,
    /// First cgroup path (container context).
    pub cgroup: Option<String>,
    /// Partial read because of permissions.
    pub restricted: bool,
}

impl ProcInfo {
    pub fn cmdline(&self) -> String {
        self.argv.join(" ")
    }

    /// Best display name: comm, or argv[0] basename.
    pub fn name(&self) -> &str {
        if !self.comm.is_empty() {
            &self.comm
        } else {
            self.argv
                .first()
                .map(|a| paths::file_name(a))
                .unwrap_or("?")
        }
    }

    pub fn in_container(&self) -> bool {
        self.cgroup.as_deref().is_some_and(|c| {
            c.contains("docker")
                || c.contains("kubepods")
                || c.contains("containerd")
                || c.contains("libpod")
                || c.contains("lxc")
        })
    }
}

/// `socket:[12345]` -> 12345
pub fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_link() {
        assert_eq!(socket_inode("socket:[4242]"), Some(4242));
        assert_eq!(socket_inode("pipe:[1]"), None);
        assert_eq!(socket_inode("/dev/null"), None);
    }

    #[test]
    fn names() {
        let p = ProcInfo {
            argv: vec!["/usr/bin/foo".into(), "-x".into()],
            exe: Some("/tmp/a (deleted)".into()),
            ..Default::default()
        };
        assert_eq!(p.name(), "foo");
        assert_eq!(p.cmdline(), "/usr/bin/foo -x");
    }
}
