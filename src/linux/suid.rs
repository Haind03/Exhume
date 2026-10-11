//! SUID/SGID file sweep (lstat only, symlinks are never followed).

use std::fs;
use std::os::unix::fs::MetadataExt;

use super::{now, read_text};
use crate::core::persistrules::{suid_entry, Entry};

const DEFAULT_ROOTS: &[&str] = &[
    "/bin", "/sbin", "/usr", "/lib", "/lib64", "/opt", "/tmp", "/var/tmp", "/dev/shm", "/home",
    "/root", "/srv", "/etc", "/var/www", "/var/lib", "/boot",
];

/// Pseudo and remote filesystems the deep sweep must not descend into.
const SKIP_FS: &[&str] = &[
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "devpts",
    "debugfs",
    "tracefs",
    "securityfs",
    "pstore",
    "bpf",
    "configfs",
    "fusectl",
    "mqueue",
    "hugetlbfs",
    "autofs",
    "binfmt_misc",
    "efivarfs",
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "sshfs",
    "fuse.sshfs",
    "9p",
    "ceph",
    "glusterfs",
    "nsfs",
    "overlay",
    "squashfs",
];

fn skip_mounts() -> Vec<String> {
    read_text("/proc/self/mounts", 4 << 20)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 3 && SKIP_FS.contains(&f[2]) && f[1] != "/")
                .then(|| f[1].replace("\\040", " "))
        })
        .collect()
}

pub fn sweep(deep: bool, owns: &(dyn Fn(&str) -> Option<bool> + Sync)) -> (Vec<Entry>, usize) {
    let skip = skip_mounts();
    // Resolve /bin -> /usr/bin style symlinks so nothing is walked twice.
    let mut roots: Vec<String> = if deep {
        vec!["/".into()]
    } else {
        DEFAULT_ROOTS
            .iter()
            .filter_map(|r| fs::canonicalize(r).ok())
            .map(|p| p.to_string_lossy().into_owned())
            .collect()
    };
    roots.sort();
    roots.dedup();
    let all = roots.clone();
    roots.retain(|r| {
        !all.iter()
            .any(|o| o != r && r.starts_with(&format!("{}/", o.trim_end_matches('/'))))
    });
    let fixed_skip = [
        "/proc",
        "/sys",
        "/run/user",
        "/var/lib/docker",
        "/var/lib/containers",
        "/var/lib/containerd",
        "/snap",
        "/var/lib/snapd/snaps",
    ];
    let now = now();
    let mut out = Vec::new();
    let mut seen = 0usize;
    let mut stack: Vec<(String, u32)> = roots.into_iter().map(|r| (r, 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        if depth > 40 || fixed_skip.contains(&dir.as_str()) || skip.contains(&dir) {
            continue;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let path = e.path().to_string_lossy().into_owned();
            let Ok(m) = fs::symlink_metadata(&path) else {
                continue;
            };
            if m.is_dir() {
                stack.push((path, depth + 1));
            } else if m.is_file() {
                seen += 1;
                let mode = m.mode();
                if mode & 0o6000 != 0 {
                    if let Some(entry) = suid_entry(
                        &path,
                        mode,
                        owns(&path),
                        Some(m.mtime().max(0) as u64),
                        Some(m.ctime().max(0) as u64),
                        now,
                    ) {
                        out.push(entry);
                    }
                }
            }
        }
    }
    (out, seen)
}
