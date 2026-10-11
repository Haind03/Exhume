//! Socket tables from /proc/net, mapped to processes through the socket inodes in /proc/<pid>/fd.

use std::collections::HashMap;

use super::read_text;
use crate::core::netrules::{parse_inet_table, parse_packet_table, SocketRow};
use crate::core::ProcInfo;

pub fn sockets(procs: &[ProcInfo]) -> Vec<SocketRow> {
    let mut rows = Vec::new();
    for proto in ["tcp", "tcp6", "udp", "udp6", "raw", "raw6"] {
        if let Some(t) = read_text(format!("/proc/net/{proto}"), 64 << 20) {
            rows.extend(parse_inet_table(proto, &t));
        }
    }
    if let Some(t) = read_text("/proc/net/packet", 4 << 20) {
        rows.extend(parse_packet_table(&t));
    }
    let mut owner: HashMap<u64, &ProcInfo> = HashMap::new();
    for p in procs {
        for i in &p.sockets {
            owner.entry(*i).or_insert(p);
        }
    }
    for r in &mut rows {
        if let Some(p) = owner.get(&r.inode) {
            r.pid = Some(p.pid);
            r.process = Some(p.name().to_string());
            r.exe = p.exe.clone();
        }
    }
    // Keep the inventory focused: listeners, bound sockets and live connections.
    rows.retain(|r| !matches!(r.state.as_str(), "TIME_WAIT" | "CLOSE" | "FIN_WAIT2"));
    rows
}

/// Socket inode -> description, for TCP/UDP sockets only (used for reverse-shell stdio checks).
pub fn inet_map(rows: &[SocketRow]) -> HashMap<u64, String> {
    rows.iter()
        .filter(|r| r.proto.starts_with("tcp") || r.proto.starts_with("udp"))
        .map(|r| (r.inode, r.summary()))
        .collect()
}
