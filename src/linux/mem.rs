//! /proc/<pid>/maps and read-only access to /proc/<pid>/mem (pread, never ptrace-stops the target).

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::FileExt;

use super::read_text;
use crate::core::memrules::{parse_maps, peek_candidates, Mapping};

pub fn maps(pid: u32) -> Option<Vec<Mapping>> {
    read_text(format!("/proc/{pid}/maps"), 32 << 20).map(|t| parse_maps(&t))
}

pub fn open_mem(pid: u32) -> Option<File> {
    File::open(format!("/proc/{pid}/mem")).ok()
}

/// Read up to `len` bytes at `addr`; stops at the first unreadable page.
pub fn read_at(f: &File, addr: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut got = 0usize;
    while got < len {
        match f.read_at(&mut buf[got..], addr + got as u64) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    buf.truncate(got);
    buf
}

/// First 64 bytes of each candidate region (ELF header check).
pub fn peeks(f: Option<&File>, maps: &[Mapping], deep: bool) -> HashMap<u64, Vec<u8>> {
    let mut out = HashMap::new();
    let Some(f) = f else { return out };
    for m in peek_candidates(maps, deep) {
        let b = read_at(f, m.start, 64);
        if !b.is_empty() {
            out.insert(m.start, b);
        }
    }
    out
}
