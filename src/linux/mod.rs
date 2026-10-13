//! Linux collectors. Everything here gathers raw data read-only and hands it to `crate::core` rules.
//! Nothing on the host is written, signalled (kill uses signal 0) or modified.

pub mod governor;
pub mod mem;
pub mod net;
pub mod persist;
pub mod pkg;
pub mod procs;
pub mod rootkit;
pub mod suid;
pub mod walk;
pub mod web;
#[cfg(feature = "yara")]
pub mod yara;

use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Count of reads refused with EACCES/EPERM, reported as a coverage limitation.
pub static DENIED: AtomicUsize = AtomicUsize::new(0);

fn note_err(e: &std::io::Error) {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        DENIED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Open a path for reading only if it is a regular file.
///
/// The open is non-blocking and the type is checked on the opened descriptor (no race with a
/// separate stat), so a FIFO or device planted where Exhume reads (a cron.d entry, a web root,
/// a persistence target) cannot hang the scan.
pub fn open_regular(p: impl AsRef<Path>) -> std::io::Result<fs::File> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(p.as_ref())?;
    if f.metadata()?.is_file() {
        Ok(f)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ))
    }
}

/// Read a text file, at most `cap` bytes, lossily decoded.
pub fn read_text(p: impl AsRef<Path>, cap: usize) -> Option<String> {
    let f = open_regular(p).map_err(|e| note_err(&e)).ok()?;
    let mut buf = Vec::new();
    f.take(cap as u64)
        .read_to_end(&mut buf)
        .map_err(|e| note_err(&e))
        .ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

pub fn read_bytes(p: impl AsRef<Path>, cap: usize) -> Option<Vec<u8>> {
    let f = open_regular(p).map_err(|e| note_err(&e)).ok()?;
    let mut buf = Vec::new();
    f.take(cap as u64)
        .read_to_end(&mut buf)
        .map_err(|e| note_err(&e))
        .ok()?;
    Some(buf)
}

pub fn read_link(p: impl AsRef<Path>) -> Option<String> {
    fs::read_link(p.as_ref())
        .map_err(|e| note_err(&e))
        .ok()
        .map(|t| t.to_string_lossy().into_owned())
}

pub fn mtime(p: impl AsRef<Path>) -> Option<u64> {
    fs::symlink_metadata(p.as_ref())
        .ok()
        .map(|m| m.mtime().max(m.ctime()).max(0) as u64)
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn hostname() -> String {
    read_text("/proc/sys/kernel/hostname", 256)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

pub fn kernel() -> String {
    let rel = read_text("/proc/sys/kernel/osrelease", 256).unwrap_or_default();
    let ver = read_text("/proc/sys/kernel/version", 256).unwrap_or_default();
    format!("{} {}", rel.trim(), ver.trim()).trim().to_string()
}

/// Numeric entries of /proc (thread-group leaders as the kernel lists them).
pub fn list_pids() -> Vec<u32> {
    let mut v: Vec<u32> = fs::read_dir("/proc")
        .map(|rd| {
            rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    v.sort_unstable();
    v
}

/// Files directly in `dir` (regular files and symlinks), sorted.
pub fn dir_files(dir: &str) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| !t.is_dir()).unwrap_or(false))
                .map(|e| e.path().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Human users' home directories plus root, from /etc/passwd: (user, home).
pub fn homes() -> Vec<(String, String)> {
    let mut v = Vec::new();
    for l in read_text("/etc/passwd", 1 << 20)
        .unwrap_or_default()
        .lines()
    {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let (user, uid, home) = (f[0], f[2].parse::<u32>().unwrap_or(0), f[5]);
        let real =
            uid == 0 || uid >= 1000 || !f[6].ends_with("nologin") && !f[6].ends_with("false");
        if real
            && home.starts_with('/')
            && home != "/"
            && Path::new(home).is_dir()
            && !v.iter().any(|(_, h): &(String, String)| h == home)
        {
            v.push((user.to_string(), home.to_string()));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_and_devices_are_not_read() {
        let dir = std::env::temp_dir().join(format!("exhume-fifo-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("planted");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        // Would block forever with a plain open() and no writer.
        assert!(read_text(&fifo, 1024).is_none());
        assert!(read_bytes(&fifo, 1024).is_none());
        assert!(read_text("/dev/zero", 16).is_none());
        let file = dir.join("regular");
        fs::write(&file, "ok").unwrap();
        assert_eq!(read_text(&file, 1024).as_deref(), Some("ok"));
        // procfs files report as regular files and stay readable.
        assert!(read_text("/proc/self/status", 4096).is_some());
        fs::remove_dir_all(&dir).unwrap();
    }
}
