//! Finding model and report output (console + JSON).

use serde::Serialize;
use std::fmt;

use super::netrules::SocketRow;
use super::resources::ScanStats;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn bump(self) -> Severity {
        match self {
            Severity::Info => Severity::Low,
            Severity::Low => Severity::Medium,
            Severity::Medium => Severity::High,
            Severity::High | Severity::Critical => Severity::Critical,
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" | "crit" => Some(Severity::Critical),
            _ => None,
        }
    }

    fn color(self) -> &'static str {
        match self {
            Severity::Info => "\x1b[90m",
            Severity::Low => "\x1b[36m",
            Severity::Medium => "\x1b[33m",
            Severity::High => "\x1b[91m",
            Severity::Critical => "\x1b[97;41m",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        };
        f.pad(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Process,
    Memory,
    Injection,
    Rootkit,
    Persistence,
    Webshell,
    Network,
    Integrity,
    #[cfg_attr(not(feature = "yara"), allow(dead_code))]
    Yara,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Category::Process => "process",
            Category::Memory => "memory",
            Category::Injection => "injection",
            Category::Rootkit => "rootkit",
            Category::Persistence => "persistence",
            Category::Webshell => "webshell",
            Category::Network => "network",
            Category::Integrity => "integrity",
            Category::Yara => "yara",
        };
        f.pad(s)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: Category,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// MITRE ATT&CK technique IDs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mitre: Vec<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

impl Finding {
    pub fn new(severity: Severity, category: Category, title: impl Into<String>) -> Self {
        Finding {
            severity,
            category,
            title: title.into(),
            pid: None,
            process: None,
            path: None,
            address: None,
            mitre: Vec::new(),
            details: Vec::new(),
        }
    }

    pub fn proc(mut self, pid: u32, name: &str) -> Self {
        self.pid = Some(pid);
        self.process = Some(name.to_string());
        self
    }

    pub fn path(mut self, p: impl Into<String>) -> Self {
        self.path = Some(p.into());
        self
    }

    pub fn addr(mut self, a: u64) -> Self {
        self.address = Some(format!("0x{a:016x}"));
        self
    }

    pub fn mitre(mut self, ids: &[&'static str]) -> Self {
        for id in ids {
            if !self.mitre.contains(id) {
                self.mitre.push(id);
            }
        }
        self
    }

    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.details.push(d.into());
        self
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub tool: &'static str,
    pub version: &'static str,
    pub host: String,
    pub kernel: String,
    pub started: String,
    pub root: bool,
    pub deep: bool,
    pub processes_scanned: usize,
    /// Coverage gaps (permission denied, feature unavailable) so a clean result is not over-trusted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
    pub findings: Vec<Finding>,
    /// Socket inventory (listening and established), mapped to owning processes.
    pub sockets: Vec<SocketRow>,
    /// Threads, resource control and per-phase timings.
    pub stats: ScanStats,
}

impl Report {
    pub fn sort(&mut self) {
        self.findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(a.category.cmp(&b.category))
                .then(a.pid.cmp(&b.pid))
                .then(a.title.cmp(&b.title))
                .then(a.path.cmp(&b.path))
        });
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    pub fn count(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }

    /// Drop findings below `min` (applied before every output so console, JSON and HTML agree).
    pub fn retain_min(&mut self, min: Severity) {
        self.findings.retain(|f| f.severity >= min);
    }

    /// Process exit code: 2 when anything High or Critical was found.
    pub fn exit_code(&self) -> i32 {
        if self.max_severity().is_some_and(|s| s >= Severity::High) {
            2
        } else {
            0
        }
    }

    pub fn print(&self, color: bool) {
        let (reset, dim, bold) = if color {
            ("\x1b[0m", "\x1b[90m", "\x1b[1m")
        } else {
            ("", "", "")
        };
        println!();
        for f in &self.findings {
            let c = if color { f.severity.color() } else { "" };
            print!(
                "{c}[{:^8}]{reset} {bold}{}{reset} {dim}({}){reset}",
                f.severity, f.title, f.category
            );
            if let (Some(pid), Some(name)) = (f.pid, &f.process) {
                print!("  {name} [pid {pid}]");
            }
            println!();
            if let Some(p) = &f.path {
                println!("           {dim}path:{reset} {p}");
            }
            if let Some(a) = &f.address {
                println!("           {dim}addr:{reset} {a}");
            }
            for d in &f.details {
                println!("           {dim}-{reset} {d}");
            }
            if !f.mitre.is_empty() {
                println!("           {dim}att&ck: {}{reset}", f.mitre.join(", "));
            }
        }
        println!();
        let listening = self
            .sockets
            .iter()
            .filter(|s| s.state == "LISTEN" || s.state == "UNCONN")
            .count();
        println!(
            "{bold}Summary:{reset} {} processes, {} sockets ({} listening/bound), {} findings  (critical {}, high {}, medium {}, low {}, info {})",
            self.processes_scanned,
            self.sockets.len(),
            listening,
            self.findings.len(),
            self.count(Severity::Critical),
            self.count(Severity::High),
            self.count(Severity::Medium),
            self.count(Severity::Low),
            self.count(Severity::Info),
        );
        let s = &self.stats;
        if s.threads > 0 {
            let phases = s
                .phases
                .iter()
                .map(|(n, t)| format!("{n} {t:.1}s"))
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "{dim}Performance: {} threads{}{}, paused {:.1}s for --cpulimit {}%; {}{reset}",
                s.threads,
                if s.soft { ", soft mode" } else { "" },
                if s.lowprio { ", low priority" } else { "" },
                s.paused_secs,
                s.cpulimit,
                phases
            );
        }
        for l in &self.limitations {
            println!("{dim}Limitation: {l}{reset}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order_and_bump() {
        assert!(Severity::Critical > Severity::High);
        assert_eq!(Severity::Low.bump(), Severity::Medium);
        assert_eq!(Severity::Critical.bump(), Severity::Critical);
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
        assert_eq!(Severity::parse("bogus"), None);
    }

    #[test]
    fn sort_puts_critical_first() {
        let mut r = Report::default();
        r.findings
            .push(Finding::new(Severity::Low, Category::Process, "a"));
        r.findings
            .push(Finding::new(Severity::Critical, Category::Memory, "b"));
        r.sort();
        assert_eq!(r.findings[0].severity, Severity::Critical);
        assert_eq!(r.max_severity(), Some(Severity::Critical));
    }

    #[test]
    fn exit_code_and_filter() {
        let mut r = Report::default();
        assert_eq!(r.exit_code(), 0);
        r.findings
            .push(Finding::new(Severity::Medium, Category::Process, "m"));
        assert_eq!(r.exit_code(), 0);
        r.findings
            .push(Finding::new(Severity::High, Category::Process, "h"));
        assert_eq!(r.exit_code(), 2);
        r.retain_min(Severity::High);
        assert_eq!(r.findings.len(), 1);
    }

    #[test]
    fn mitre_dedup() {
        let f = Finding::new(Severity::Low, Category::Process, "x")
            .mitre(&["T1059.004"])
            .mitre(&["T1059.004", "T1036"]);
        assert_eq!(f.mitre, vec!["T1059.004", "T1036"]);
    }
}
