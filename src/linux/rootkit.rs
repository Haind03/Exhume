//! Rootkit cross-view collectors: PID brute force, module views, kernel taint and eBPF programs.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

use rayon::prelude::*;

use super::{list_pids, read_link, read_text};
use crate::core::report::Finding;
use crate::core::rootkit::{self, BpfProg};

/// Every task the kernel shows us: process directories plus their /proc/<pid>/task entries.
fn listed_tasks() -> HashSet<u32> {
    let mut s = HashSet::new();
    for pid in list_pids() {
        s.insert(pid);
        if let Ok(rd) = fs::read_dir(format!("/proc/{pid}/task")) {
            s.extend(rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok()));
        }
    }
    s
}

/// kill(pid, 0) sends no signal; it only checks existence (EPERM still means the pid exists).
fn alive(pid: u32) -> bool {
    let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub fn hidden_processes() -> Vec<Finding> {
    let max: u32 = read_text("/proc/sys/kernel/pid_max", 64)
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(32768)
        .min(4_194_304);
    let listed = listed_tasks();
    let probed: Vec<u32> = (1..=max).into_par_iter().filter(|&p| alive(p)).collect();
    let first = rootkit::crossview_pids(&listed, &probed);
    if first.is_empty() {
        return Vec::new();
    }
    // Second pass removes processes that were simply born between the two views.
    let listed2 = listed_tasks();
    let mut out = Vec::new();
    for pid in first
        .into_iter()
        .filter(|p| !listed2.contains(p) && alive(*p))
    {
        let status = read_text(format!("/proc/{pid}/status"), 8192).unwrap_or_default();
        let tgid: Option<u32> = status
            .lines()
            .find_map(|l| l.strip_prefix("Tgid:"))
            .and_then(|v| v.trim().parse().ok());
        if let Some(t) = tgid {
            if t != pid && listed2.contains(&t) {
                continue; // a thread of a visible process
            }
        }
        let name = status
            .lines()
            .find_map(|l| l.strip_prefix("Name:"))
            .map(|s| s.trim().to_string());
        let exe = read_link(format!("/proc/{pid}/exe"));
        out.push(rootkit::hidden_pid_finding(
            pid,
            name.as_deref(),
            exe.as_deref(),
        ));
    }
    out
}

pub fn modules(root: bool) -> Vec<Finding> {
    let Some(pm) = read_text("/proc/modules", 8 << 20) else {
        return Vec::new();
    };
    let mods = rootkit::parse_proc_modules(&pm);
    let mut sys = BTreeSet::new();
    if let Ok(rd) = fs::read_dir("/sys/module") {
        for e in rd.flatten() {
            if e.path().join("initstate").exists() {
                sys.insert(e.file_name().to_string_lossy().into_owned());
            }
        }
    }
    // Symbol names are readable without root (addresses are zeroed by kptr_restrict).
    let ks = read_text("/proc/kallsyms", 256 << 20).map(|t| rootkit::kallsyms_modules(&t));
    let ks = ks.filter(|k| !k.is_empty() || root);
    // Re-read /proc/modules to drop modules loaded or unloaded while we looked.
    let mods2 = read_text("/proc/modules", 8 << 20)
        .map(|t| rootkit::parse_proc_modules(&t))
        .unwrap_or_default();
    let names2: HashSet<String> = mods2.iter().map(|m| m.name.clone()).collect();
    let mut f = rootkit::module_findings(&mods, &sys, ks.as_ref());
    f.retain(|x| {
        let n = x
            .path
            .as_deref()
            .and_then(|p| p.strip_prefix("module "))
            .unwrap_or("");
        !(x.title.contains("not in /proc/modules") || x.title.contains("hidden from"))
            || !names2.contains(n)
    });
    f
}

pub fn taint() -> Option<Finding> {
    let v: u64 = read_text("/proc/sys/kernel/tainted", 64)?
        .trim()
        .parse()
        .ok()?;
    rootkit::taint_finding(v)
}

// ---- eBPF via the bpf(2) syscall (needs CAP_SYS_ADMIN / CAP_BPF).

const BPF_PROG_GET_NEXT_ID: libc::c_long = 11;
const BPF_PROG_GET_FD_BY_ID: libc::c_long = 13;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_long = 15;

#[repr(C)]
#[derive(Default)]
struct IdAttr {
    id: u32,
    next_id: u32,
    open_flags: u32,
    _pad: [u32; 29],
}

#[repr(C)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
    _pad: [u64; 14],
}

fn bpf(cmd: libc::c_long, attr: *mut u8, size: usize) -> libc::c_long {
    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size as libc::c_uint) }
}

/// prog_id -> holders, from the `prog_id:` lines of /proc/<pid>/fdinfo.
fn bpf_holders() -> HashMap<u32, Vec<(u32, String)>> {
    let mut m: HashMap<u32, Vec<(u32, String)>> = HashMap::new();
    for pid in list_pids() {
        let Ok(rd) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        let mut comm = None;
        for e in rd.flatten() {
            let Ok(t) = fs::read_link(e.path()) else {
                continue;
            };
            if t.to_string_lossy() != "anon_inode:bpf-prog" {
                continue;
            }
            let fdinfo = read_text(
                format!("/proc/{pid}/fdinfo/{}", e.file_name().to_string_lossy()),
                4096,
            )
            .unwrap_or_default();
            if let Some(id) = fdinfo
                .lines()
                .find_map(|l| l.strip_prefix("prog_id:"))
                .and_then(|v| v.trim().parse::<u32>().ok())
            {
                let c = comm
                    .get_or_insert_with(|| {
                        read_text(format!("/proc/{pid}/comm"), 64)
                            .unwrap_or_default()
                            .trim()
                            .to_string()
                    })
                    .clone();
                let v = m.entry(id).or_default();
                if !v.iter().any(|(p, _)| *p == pid) {
                    v.push((pid, c));
                }
            }
        }
    }
    m
}

/// Loaded eBPF programs. Err(reason) when the kernel refuses enumeration.
pub fn bpf_programs() -> Result<Vec<BpfProg>, String> {
    let mut out = Vec::new();
    let holders = bpf_holders();
    let mut id = 0u32;
    loop {
        let mut a = IdAttr {
            id,
            ..Default::default()
        };
        if bpf(
            BPF_PROG_GET_NEXT_ID,
            &mut a as *mut _ as *mut u8,
            std::mem::size_of::<IdAttr>(),
        ) != 0
        {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENOENT) {
                break;
            }
            return Err(format!("bpf(PROG_GET_NEXT_ID): {e}"));
        }
        id = a.next_id;
        let mut g = IdAttr {
            id,
            ..Default::default()
        };
        let fd = bpf(
            BPF_PROG_GET_FD_BY_ID,
            &mut g as *mut _ as *mut u8,
            std::mem::size_of::<IdAttr>(),
        );
        let mut prog = BpfProg {
            id,
            holders: holders.get(&id).cloned().unwrap_or_default(),
            ..Default::default()
        };
        if fd >= 0 {
            let mut info = [0u8; 256];
            let mut ia = InfoAttr {
                bpf_fd: fd as u32,
                info_len: info.len() as u32,
                info: info.as_mut_ptr() as u64,
                _pad: [0; 14],
            };
            if bpf(
                BPF_OBJ_GET_INFO_BY_FD,
                &mut ia as *mut _ as *mut u8,
                std::mem::size_of::<InfoAttr>(),
            ) == 0
            {
                prog.prog_type = u32::from_ne_bytes(info[0..4].try_into().unwrap());
                prog.tag = info[8..16].iter().map(|b| format!("{b:02x}")).collect();
                prog.uid = u32::from_ne_bytes(info[48..52].try_into().unwrap());
                let name = &info[64..80];
                let n = name.iter().position(|&c| c == 0).unwrap_or(16);
                prog.name = String::from_utf8_lossy(&name[..n]).into_owned();
            }
            unsafe { libc::close(fd as i32) };
        }
        out.push(prog);
        if out.len() > 100_000 {
            break;
        }
    }
    Ok(out)
}

pub fn bpf_available() -> bool {
    Path::new("/sys/fs/bpf").exists()
        || Path::new("/proc/sys/kernel/unprivileged_bpf_disabled").exists()
}
