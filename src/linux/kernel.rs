//! Kernel hook and kernel log collectors: tracefs/debugfs ftrace and kprobe listings and the
//! /dev/kmsg ring buffer. Read-only: nothing is mounted and no tracing is switched on.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

use super::read_text;
use crate::core::kernelrules::{self, KmsgRecord};
use crate::core::report::Finding;

/// tracefs mount points, newest first (debugfs/tracing is the pre-4.1 location).
const TRACEFS: &[&str] = &["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

fn loaded_modules() -> BTreeSet<String> {
    read_text("/proc/modules", 8 << 20)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect()
}

fn livepatches() -> BTreeSet<String> {
    fs::read_dir("/sys/kernel/livepatch")
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// ftrace hooks and kprobes. Returns findings and limitations. `bpf_kprobes` says whether
/// kprobe-type eBPF programs are loaded.
pub fn hooks(bpf_kprobes: bool) -> (Vec<Finding>, Vec<String>) {
    let mut out = Vec::new();
    let mut limits = Vec::new();
    let tracefs = TRACEFS
        .iter()
        .find(|d| std::path::Path::new(&format!("{d}/enabled_functions")).exists());
    match tracefs {
        Some(d) => {
            let ef = format!("{d}/enabled_functions");
            match read_text(&ef, 64 << 20) {
                Some(t) => {
                    // /proc/modules is read after the listing, so a module loaded meanwhile is
                    // not reported as hidden.
                    let hooks = kernelrules::parse_enabled_functions(&t);
                    out.extend(kernelrules::ftrace_findings(
                        &hooks,
                        &loaded_modules(),
                        &livepatches(),
                    ));
                }
                None => limits.push(format!("{ef} not readable: ftrace hooks not checked")),
            }
            if let Some(t) = read_text(format!("{d}/kprobe_events"), 8 << 20) {
                let p = kernelrules::parse_kprobe_events(&t);
                out.extend(kernelrules::kprobe_findings(
                    &p,
                    &format!("{d}/kprobe_events"),
                    bpf_kprobes,
                ));
            }
        }
        None => limits.push(
            "tracefs is not mounted: ftrace hooks (a common LKM rootkit technique) not checked"
                .into(),
        ),
    }
    if let Some(t) = read_text("/sys/kernel/debug/kprobes/list", 16 << 20) {
        let p = kernelrules::parse_kprobes_list(&t);
        out.extend(kernelrules::kprobe_findings(
            &p,
            "/sys/kernel/debug/kprobes/list",
            bpf_kprobes,
        ));
    }
    (out, limits)
}

/// Reads every record still in the kernel ring buffer without blocking.
fn kmsg_records() -> Result<Vec<KmsgRecord>, String> {
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/kmsg")
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    // One record per read(); records are at most 8 KiB (CONSOLE_EXT_LOG_MAX).
    let mut buf = vec![0u8; 16 << 10];
    for _ in 0..1_000_000 {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Some(r) = kernelrules::parse_kmsg_record(&String::from_utf8_lossy(&buf[..n]))
                {
                    out.push(r);
                }
            }
            // EPIPE: records were overwritten while we read; the next read continues.
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(out)
}

fn boot_time() -> u64 {
    read_text("/proc/stat", 1 << 20)
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

/// Kernel log indicators. `since` (epoch seconds) drops older records.
pub fn kernel_log(since: Option<u64>) -> (Vec<Finding>, Vec<String>) {
    match kmsg_records() {
        Ok(r) => (
            kernelrules::kmsg_findings(&r, &loaded_modules(), boot_time(), since),
            Vec::new(),
        ),
        Err(e) => (
            Vec::new(),
            vec![format!("kernel log (/dev/kmsg) not readable: {e}")],
        ),
    }
}
