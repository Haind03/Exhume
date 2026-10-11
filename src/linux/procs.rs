//! Process snapshot from /proc/<pid>.

use std::fs;
use std::path::Path;

use super::{read_bytes, read_link, read_text};
use crate::core::paths::{memfd_name, strip_deleted};
use crate::core::{socket_inode, ProcInfo};

const PF_KTHREAD: u64 = 0x0020_0000;

/// `pid (comm) S ppid ...` -> (ppid, flags). comm may contain spaces and ')'.
pub fn parse_stat(s: &str) -> Option<(u32, u64)> {
    let rest = &s[s.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    Some((f.get(1)?.parse().ok()?, f.get(6)?.parse().ok()?))
}

fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(':').map(str::trim))
}

pub fn collect(pid: u32) -> Option<ProcInfo> {
    let base = format!("/proc/{pid}");
    let stat = read_text(format!("{base}/stat"), 4096)?;
    let (ppid, flags) = parse_stat(&stat)?;
    let status = read_text(format!("{base}/status"), 16384).unwrap_or_default();
    let mut p = ProcInfo {
        pid,
        ppid,
        kthread: flags & PF_KTHREAD != 0,
        comm: read_text(format!("{base}/comm"), 256)
            .map(|s| s.trim_end_matches('\n').to_string())
            .unwrap_or_default(),
        tracer_pid: status_field(&status, "TracerPid")
            .and_then(|t| t.parse().ok())
            .unwrap_or(0),
        ..Default::default()
    };
    if p.kthread {
        return Some(p);
    }
    if let Some(raw) = read_bytes(format!("{base}/cmdline"), 64 * 1024) {
        p.argv = raw
            .split(|&b| b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
    }
    match read_link(format!("{base}/exe")) {
        Some(e) => {
            let (path, deleted) = strip_deleted(&e);
            if deleted && memfd_name(&e).is_none() {
                p.exe_replaced = Path::new(path).exists();
            }
            p.exe = Some(e);
        }
        None => p.restricted = true,
    }
    match fs::read_dir(format!("{base}/fd")) {
        Ok(rd) => {
            for e in rd.flatten() {
                let Some(fd) = e.file_name().to_str().and_then(|s| s.parse::<usize>().ok()) else {
                    continue;
                };
                let Ok(t) = fs::read_link(e.path()) else {
                    continue;
                };
                let t = t.to_string_lossy().into_owned();
                if let Some(i) = socket_inode(&t) {
                    p.sockets.push(i);
                }
                if fd < 3 {
                    p.stdio[fd] = Some(t);
                }
            }
        }
        Err(_) => p.restricted = true,
    }
    match read_bytes(format!("{base}/environ"), 256 * 1024) {
        Some(env) => {
            for kv in env.split(|&b| b == 0) {
                let kv = String::from_utf8_lossy(kv);
                if let Some((k, v)) = kv.split_once('=') {
                    if matches!(k, "LD_PRELOAD" | "LD_AUDIT" | "LD_LIBRARY_PATH") {
                        p.ld_env.push((k.to_string(), v.to_string()));
                    }
                }
            }
        }
        None => p.restricted = true,
    }
    p.cgroup = read_text(format!("{base}/cgroup"), 4096).and_then(|c| {
        c.lines()
            .next()
            .map(|l| l.rsplit(':').next().unwrap_or("").to_string())
    });
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parsing() {
        let s = "1234 (evil) proc) S 1 1234 1234 0 -1 4194560 100 0 0 0";
        assert_eq!(parse_stat(s), Some((1, 4194560)));
        let k = "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0";
        let (_, f) = parse_stat(k).unwrap();
        assert!(f & PF_KTHREAD != 0);
    }

    #[test]
    fn self_snapshot() {
        let p = collect(std::process::id()).expect("own process readable");
        assert!(!p.kthread);
        assert!(p.exe.is_some());
        assert!(!p.argv.is_empty());
    }
}
