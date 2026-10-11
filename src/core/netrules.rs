//! Socket inventory from /proc/net/{tcp,tcp6,udp,udp6,raw,raw6,packet} mapped to owning processes
//! through socket inodes, and rules for backdoor listeners and raw-packet sniffers.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

use super::paths::{memfd_name, strip_deleted, suspicious_location};
use super::procrules::{is_interpreter, is_shell};
use super::report::{Category, Finding, Severity};

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct SocketRow {
    pub proto: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub inode: u64,
    pub uid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(skip)]
    pub local_port: u16,
    #[serde(skip)]
    pub remote_port: u16,
}

impl SocketRow {
    pub fn listening(&self) -> bool {
        self.state == "LISTEN" || (self.proto.starts_with("udp") && self.state == "UNCONN")
    }

    pub fn summary(&self) -> String {
        if self.remote_port == 0 && !self.proto.starts_with("packet") {
            format!("{} {} {}", self.proto, self.local, self.state)
        } else {
            format!(
                "{} {} -> {} {}",
                self.proto, self.local, self.remote, self.state
            )
        }
    }
}

fn tcp_state(code: u8, udp: bool) -> &'static str {
    match code {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 if udp => "UNCONN",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// `0100007F:0277` -> ("127.0.0.1:631", 631); IPv6 uses four little-endian words.
pub fn parse_addr(s: &str) -> Option<(String, u16)> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    match ip.len() {
        8 => {
            let v = u32::from_str_radix(ip, 16).ok()?;
            Some((format!("{}:{port}", Ipv4Addr::from(v.swap_bytes())), port))
        }
        32 => {
            let mut b = [0u8; 16];
            for w in 0..4 {
                let word = u32::from_str_radix(&ip[w * 8..w * 8 + 8], 16).ok()?;
                b[w * 4..w * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            let a = Ipv6Addr::from(b);
            let shown = match a.to_ipv4_mapped() {
                Some(v4) => v4.to_string(),
                None => a.to_string(),
            };
            Some((format!("[{shown}]:{port}"), port))
        }
        _ => None,
    }
}

/// Parse /proc/net/{tcp,udp,raw}[6].
pub fn parse_inet_table(proto: &str, text: &str) -> Vec<SocketRow> {
    let udp = proto.starts_with("udp") || proto.starts_with("raw");
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let (local, lp) = parse_addr(f[1])?;
            let (remote, rp) = parse_addr(f[2])?;
            let st = u8::from_str_radix(f[3], 16).ok()?;
            Some(SocketRow {
                proto: proto.to_string(),
                local,
                remote,
                state: tcp_state(st, udp).to_string(),
                inode: f[9].parse().ok()?,
                uid: f[7].parse().unwrap_or(0),
                local_port: lp,
                remote_port: rp,
                ..Default::default()
            })
        })
        .collect()
}

/// Parse /proc/net/packet (AF_PACKET sockets).
pub fn parse_packet_table(text: &str) -> Vec<SocketRow> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 9 {
                return None;
            }
            let ty = match f[2] {
                "3" => "raw",
                "2" => "dgram",
                _ => "other",
            };
            Some(SocketRow {
                proto: "packet".into(),
                local: format!("{ty} proto 0x{} iface {}", f[3], f[4]),
                remote: String::new(),
                state: "BOUND".into(),
                inode: f[8].parse().ok()?,
                uid: f[7].parse().unwrap_or(0),
                ..Default::default()
            })
        })
        .collect()
}

/// Ports favoured by default configs of offensive tools and IRC/botnet C2.
const BACKDOOR_PORTS: &[u16] = &[
    1337, 4444, 4445, 5554, 6666, 6667, 6697, 12345, 12346, 20034, 27374, 31337, 31338, 54321,
    65535,
];

/// Programs that open raw/packet sockets as part of normal operation.
const RAW_OK: &[&str] = &[
    "dhclient",
    "dhcpcd",
    "NetworkManager",
    "systemd-network",
    "systemd-networkd",
    "wpa_supplicant",
    "tcpdump",
    "wireshark",
    "dumpcap",
    "tshark",
    "lldpd",
    "keepalived",
    "arping",
    "ping",
    "ping6",
    "traceroute",
    "mtr-packet",
    "snort",
    "suricata",
    "zeek",
    "ntopng",
    "hostapd",
    "bird",
    "bird6",
    "pppd",
    "udhcpc",
    "cilium-agent",
    "ndppd",
    "radvd",
    "iftop",
    "nethogs",
    "darkstat",
    "arpwatch",
    "p0f",
    "avahi-daemon",
    "dnsmasq",
    "openvpn",
    "charon",
    "nmap",
    "masscan",
    "zmap",
    "ladvd",
    "vrrpd",
    "frr",
    "zebra",
    "ospfd",
    "isisd",
    "ptp4l",
    "chronyd",
    "ntpd",
    "teamd",
    "connmand",
    "iwd",
    "netifd",
    "kubelet",
    "falco",
    "packetbeat",
    "auditbeat",
    "filebeat",
    "osqueryd",
    "zabbix_agentd",
    "netdata",
    "corosync",
    "pacemakerd",
    "xdpd",
];

fn exe_problem(exe: &str) -> Option<String> {
    if let Some(m) = memfd_name(exe) {
        return Some(format!("owner runs from memfd '{m}'"));
    }
    let (p, deleted) = strip_deleted(exe);
    if let Some(why) = suspicious_location(p) {
        return Some(format!("owner binary in {why}"));
    }
    if deleted {
        return Some("owner binary deleted from disk".into());
    }
    None
}

pub fn analyze(rows: &[SocketRow], root: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    for r in rows {
        let name = r.process.clone().unwrap_or_default();
        let mk = |sev, title: &str| {
            let mut f = Finding::new(sev, Category::Network, title).detail(r.summary());
            if let Some(pid) = r.pid {
                f = f.proc(pid, &name);
            }
            if let Some(e) = &r.exe {
                f = f.path(e.clone());
            }
            f
        };

        if r.proto == "packet" || r.proto.starts_with("raw") {
            match &r.pid {
                Some(_) if RAW_OK.iter().any(|ok| name == *ok || name.starts_with(ok)) => {}
                Some(_) => {
                    let sev = if r.exe.as_deref().and_then(exe_problem).is_some() {
                        Severity::Critical
                    } else if r.proto == "packet" {
                        Severity::High
                    } else {
                        Severity::Medium
                    };
                    out.push(
                        mk(sev, if r.proto == "packet" { "Unexpected process sniffing raw packets (AF_PACKET)" } else { "Unexpected process holding a raw IP socket" })
                            .detail("passive magic-packet backdoors (BPFDoor, Symbiote-style) wait on raw sockets with a BPF filter")
                            .mitre(&["T1205.002", "T1040"]),
                    );
                }
                None if root && r.inode != 0 => {
                    out.push(
                        mk(Severity::Medium, "Raw/packet socket with no visible owner")
                            .detail("socket inode not held by any listed process (hidden process?)")
                            .mitre(&["T1205.002", "T1014"]),
                    );
                }
                None => {}
            }
            continue;
        }

        if let Some(problem) = r.exe.as_deref().and_then(exe_problem) {
            if r.listening() || r.state == "ESTABLISHED" {
                let sev = if r.exe.as_deref().and_then(memfd_name).is_some() {
                    Severity::Critical
                } else {
                    Severity::High
                };
                out.push(
                    mk(
                        sev,
                        if r.listening() {
                            "Network listener owned by a suspicious binary"
                        } else {
                            "Network connection from a suspicious binary"
                        },
                    )
                    .detail(problem)
                    .mitre(&["T1095", "T1571"]),
                );
                continue;
            }
        }

        let lname = name.to_ascii_lowercase();
        if r.listening() && r.proto.starts_with("tcp") {
            if is_shell(&lname) {
                out.push(
                    mk(
                        Severity::Critical,
                        "Shell listening on a TCP port (bind shell)",
                    )
                    .mitre(&["T1059.004", "T1571"]),
                );
                continue;
            }
            if is_interpreter(&lname)
                && !lname.starts_with("python")
                && !lname.starts_with("node")
                && !lname.starts_with("ruby")
                && !lname.starts_with("php")
            {
                out.push(
                    mk(Severity::Medium, "Scripting tool listening on a TCP port")
                        .mitre(&["T1059", "T1571"]),
                );
            }
            if lname == "nc" || lname == "ncat" || lname == "netcat" || lname == "socat" {
                out.push(mk(Severity::Medium, "netcat/socat listener").mitre(&["T1095", "T1571"]));
                continue;
            }
        }
        let port_hit = (r.listening() && BACKDOOR_PORTS.contains(&r.local_port))
            || (r.state == "ESTABLISHED" && BACKDOOR_PORTS.contains(&r.remote_port));
        if port_hit {
            out.push(
                mk(
                    Severity::Medium,
                    "Socket on a port typical of backdoors and offensive tooling",
                )
                .mitre(&["T1571"]),
            );
            continue;
        }
        if root && r.pid.is_none() && r.inode != 0 && r.state == "LISTEN" {
            out.push(
                mk(Severity::Low, "Listening socket not attributable to any process")
                    .detail("no visible process holds this socket inode: kernel service, other namespace, or a hidden process")
                    .mitre(&["T1014"]),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0000000000000000 100 0 0 10 0
   1: 0500000A:C350 04030201:115C 01 00000000:00000000 00:00000000 00000000  1000        0 2222 1 0000000000000000 20 4 30 10 -1
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3333 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4444 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn parse_v4_v6() {
        let v = parse_inet_table("tcp", TCP);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].local, "127.0.0.1:631");
        assert_eq!(v[0].state, "LISTEN");
        assert_eq!(v[1].remote, "1.2.3.4:4444");
        assert_eq!(v[1].local, "10.0.0.5:50000");
        assert_eq!(v[1].uid, 1000);
        assert_eq!(v[1].inode, 2222);
        let v6 = parse_inet_table("tcp6", TCP6);
        assert_eq!(v6[0].local, "[::]:22");
        assert_eq!(v6[1].local, "[127.0.0.1]:8080");
        let udp = parse_inet_table("udp", "h\n   0: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 5555 2 0\n");
        assert_eq!(udp[0].state, "UNCONN");
        assert!(udp[0].listening());
    }

    #[test]
    fn packet() {
        let t = "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\nffff8881 3      3    0003   2     1 0      0      9999\n";
        let p = parse_packet_table(t);
        assert_eq!(p[0].inode, 9999);
        assert!(p[0].local.starts_with("raw proto 0x0003"));
    }

    fn row(
        proto: &str,
        state: &str,
        lp: u16,
        rp: u16,
        pid: Option<u32>,
        name: &str,
        exe: &str,
    ) -> SocketRow {
        SocketRow {
            proto: proto.into(),
            local: format!("0.0.0.0:{lp}"),
            remote: format!("1.2.3.4:{rp}"),
            state: state.into(),
            inode: 1,
            pid,
            process: pid.map(|_| name.to_string()),
            exe: pid.map(|_| exe.to_string()),
            local_port: lp,
            remote_port: rp,
            ..Default::default()
        }
    }

    #[test]
    fn rules() {
        let rows = vec![
            row("tcp", "LISTEN", 22, 0, Some(1), "sshd", "/usr/sbin/sshd"),
            row("tcp", "LISTEN", 8443, 0, Some(2), "x", "/dev/shm/x"),
            row(
                "tcp",
                "ESTABLISHED",
                50000,
                4444,
                Some(3),
                "curl",
                "/usr/bin/curl",
            ),
            row("tcp", "LISTEN", 9999, 0, Some(4), "bash", "/usr/bin/bash"),
            row(
                "packet",
                "BOUND",
                0,
                0,
                Some(5),
                "dhclient",
                "/usr/sbin/dhclient",
            ),
            row(
                "packet",
                "BOUND",
                0,
                0,
                Some(6),
                "kworker",
                "/usr/lib/.x/k (deleted)",
            ),
            row("tcp", "LISTEN", 2049, 0, None, "", ""),
        ];
        let f = analyze(&rows, true);
        let t: Vec<_> = f
            .iter()
            .map(|f| (f.severity, f.title.as_str(), f.pid))
            .collect();
        assert!(t.contains(&(
            Severity::High,
            "Network listener owned by a suspicious binary",
            Some(2)
        )));
        assert!(t.contains(&(
            Severity::Medium,
            "Socket on a port typical of backdoors and offensive tooling",
            Some(3)
        )));
        assert!(t.contains(&(
            Severity::Critical,
            "Shell listening on a TCP port (bind shell)",
            Some(4)
        )));
        assert!(t.contains(&(
            Severity::Critical,
            "Unexpected process sniffing raw packets (AF_PACKET)",
            Some(6)
        )));
        assert!(t.iter().any(|x| x.0 == Severity::Low && x.2.is_none()));
        assert!(!t.iter().any(|x| x.2 == Some(1) || x.2 == Some(5)), "{t:?}");
        assert!(
            !analyze(&rows, false).iter().any(|f| f.pid.is_none()),
            "unowned sockets only judged as root"
        );
    }
}
