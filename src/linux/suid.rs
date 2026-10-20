//! SUID/SGID file sweep (lstat only, symlinks are never followed).

use std::fs;
use std::os::unix::fs::MetadataExt;

use super::walk::{par_walk, Walk};
use super::{now, read_text};
use crate::core::persistext::{capability_entry, parse_vfs_cap};
use crate::core::persistrules::{suid_entry, Entry};

/// Raw `security.capability` xattr of a file (not following symlinks).
fn file_caps(path: &str) -> Option<Vec<u8>> {
    let c = std::ffi::CString::new(path).ok()?;
    let mut buf = [0u8; 64];
    let n = unsafe {
        libc::lgetxattr(
            c.as_ptr(),
            c"security.capability".as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    (n > 0).then(|| buf[..n as usize].to_vec())
}

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
    let skip_dir =
        |path: &str, _: &str| fixed_skip.contains(&path) || skip.iter().any(|m| m == path);
    // SUID/SGID bits and file capabilities, read in the same pass over the tree.
    let visit = |path: &str, m: &std::fs::Metadata| {
        let mode = m.mode();
        let mut found = Vec::new();
        if mode & 0o6000 != 0 {
            found.extend(suid_entry(
                path,
                mode,
                owns(path),
                Some(m.mtime().max(0) as u64),
                Some(m.ctime().max(0) as u64),
                now,
            ));
        }
        if mode & 0o111 != 0 {
            if let Some((mask, eff)) = file_caps(path).and_then(|b| parse_vfs_cap(&b)) {
                let t = m.mtime().max(m.ctime()).max(0) as u64;
                found.extend(capability_entry(path, mask, eff, owns(path), Some(t)));
            }
        }
        (!found.is_empty()).then_some(found)
    };
    let (found, seen) = par_walk(
        &roots,
        &Walk {
            max_depth: 40,
            limit: usize::MAX,
            skip_dir: &skip_dir,
            visit: &visit,
        },
    );
    (found.into_iter().flatten().collect(), seen)
}
