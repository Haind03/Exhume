//! Collects autostart entries from the filesystem. Parsing and scoring live in core::persistrules.

use std::fs;
use std::path::Path;

use super::pkg::PkgDb;
use super::{dir_files, homes, mtime, read_text};
use crate::core::persistrules::{self as pr, Entry, Kind};
use crate::core::procrules::cmdline_hits;
use crate::core::report::Severity;

const CAP: usize = 1 << 20;

/// Script files (cron.daily, init.d, rc.local, update-motd.d): content lines run through the
/// command-line rules.
fn script_entry(kind: Kind, path: &str) -> Option<Entry> {
    let text = read_text(path, CAP)?;
    let mut e = Entry::new(kind, path, pr_name(path), path);
    let mut body = 0;
    for (n, l) in text.lines().enumerate() {
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') || t == "exit 0" {
            continue;
        }
        body += 1;
        for h in cmdline_hits(t) {
            e = e.floor(
                h.severity,
                format!(
                    "line {}: {} ({})",
                    n + 1,
                    h.reason,
                    crate::core::procrules::truncate(t, 160)
                ),
            );
        }
    }
    (body > 0).then_some(e)
}

fn pr_name(p: &str) -> String {
    crate::core::paths::file_name(p).to_string()
}

fn crontabs(out: &mut Vec<Entry>) {
    let mut sys = vec!["/etc/crontab".to_string()];
    sys.extend(dir_files("/etc/cron.d"));
    for f in sys {
        for (sched, user, cmd) in pr::parse_crontab(&read_text(&f, CAP).unwrap_or_default(), true) {
            let mut e = Entry::new(Kind::Cron, &f, sched, cmd);
            e.user = user;
            out.push(e);
        }
    }
    for dir in [
        "/var/spool/cron/crontabs",
        "/var/spool/cron",
        "/var/spool/cron/tabs",
    ] {
        for f in dir_files(dir) {
            let user = pr_name(&f);
            for (sched, _, cmd) in pr::parse_crontab(&read_text(&f, CAP).unwrap_or_default(), false)
            {
                let mut e =
                    Entry::new(Kind::Cron, &f, sched, cmd).floor(Severity::Info, "user crontab");
                e.user = Some(user.clone());
                out.push(e);
            }
        }
    }
    for dir in [
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ] {
        for f in dir_files(dir)
            .into_iter()
            .filter(|f| !f.ends_with(".placeholder"))
        {
            out.extend(script_entry(Kind::Cron, &f));
        }
    }
    for (job, cmd) in pr::parse_anacrontab(&read_text("/etc/anacrontab", CAP).unwrap_or_default()) {
        out.push(Entry::new(Kind::Anacron, "/etc/anacrontab", job, cmd));
    }
    for dir in [
        "/var/spool/cron/atjobs",
        "/var/spool/at",
        "/var/spool/atjobs",
    ] {
        for f in dir_files(dir).into_iter().filter(|f| !f.ends_with(".SEQ")) {
            let cmd = pr::parse_at_job(&read_text(&f, CAP).unwrap_or_default());
            out.push(
                Entry::new(Kind::At, &f, pr_name(&f), cmd).floor(Severity::Info, "pending at job"),
            );
        }
    }
}

const UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/run/systemd/transient",
    "/usr/local/lib/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/etc/systemd/user",
    "/usr/local/lib/systemd/user",
    "/usr/lib/systemd/user",
    "/lib/systemd/user",
];
const GENERATOR_DIRS: &[&str] = &[
    "/etc/systemd/system-generators",
    "/usr/local/lib/systemd/system-generators",
    "/lib/systemd/system-generators",
    "/usr/lib/systemd/system-generators",
    "/run/systemd/system-generators",
    "/etc/systemd/user-generators",
    "/usr/local/lib/systemd/user-generators",
    "/usr/lib/systemd/user-generators",
    "/run/systemd/user-generators",
];

fn unit_file(out: &mut Vec<Entry>, path: &str, unit: &str) {
    let text = read_text(path, CAP).unwrap_or_default();
    let parsed = pr::parse_unit(&text);
    if unit.ends_with(".timer") {
        let desc = parsed
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        out.push(Entry::new(Kind::SystemdTimer, path, unit, desc));
        return;
    }
    for (k, v) in parsed.into_iter().filter(|(k, _)| k.starts_with("Exec")) {
        out.push(Entry::new(
            Kind::SystemdService,
            path,
            format!("{unit} {k}"),
            v,
        ));
    }
}

fn systemd(out: &mut Vec<Entry>, user_dirs: &[String]) {
    let mut dirs: Vec<String> = UNIT_DIRS.iter().map(|s| s.to_string()).collect();
    dirs.extend(user_dirs.iter().cloned());
    let mut seen = std::collections::HashSet::new();
    for d in dirs {
        let Ok(canon) = fs::canonicalize(&d) else {
            continue;
        };
        if !seen.insert(canon) {
            continue;
        }
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let path = e.path().to_string_lossy().into_owned();
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() {
                // Enablement links point at units; one pointing into a temp dir is a red flag.
                if let Ok(t) = fs::read_link(&path) {
                    let t = t.to_string_lossy().into_owned();
                    if t != "/dev/null" && crate::core::paths::suspicious_location(&t).is_some() {
                        out.push(Entry::new(Kind::SystemdService, &path, &name, &t).floor(
                            Severity::High,
                            "unit symlink points into a suspicious location",
                        ));
                    }
                }
                continue;
            }
            if ft.is_dir() {
                // Drop-ins (foo.service.d/*.conf) can override ExecStart; .wants dirs hold symlinks.
                if name.ends_with(".d") {
                    for f in dir_files(&path)
                        .into_iter()
                        .filter(|f| f.ends_with(".conf"))
                    {
                        unit_file(out, &f, &format!("{name}/{}", pr_name(&f)));
                    }
                }
                continue;
            }
            if [".service", ".timer", ".socket", ".path"]
                .iter()
                .any(|s| name.ends_with(s))
            {
                unit_file(out, &path, &name);
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    for d in GENERATOR_DIRS {
        let Ok(canon) = fs::canonicalize(d) else {
            continue;
        };
        if !seen.insert(canon) {
            continue;
        }
        for f in dir_files(d) {
            out.push(Entry::new(Kind::SystemdGenerator, &f, pr_name(&f), &f));
        }
    }
}

fn boot_scripts(out: &mut Vec<Entry>) {
    for f in [
        "/etc/rc.local",
        "/etc/rc.d/rc.local",
        "/etc/rc.d/rc.sysinit",
    ] {
        if let Some(e) = script_entry(Kind::RcLocal, f) {
            out.push(e.floor(Severity::Info, "rc.local runs as root at boot"));
        }
    }
    for f in dir_files("/etc/init.d")
        .into_iter()
        .filter(|f| !f.ends_with("README") && !f.ends_with(".dpkg-old"))
    {
        out.extend(script_entry(Kind::InitScript, &f));
    }
    for f in dir_files("/etc/update-motd.d") {
        out.extend(script_entry(Kind::Motd, &f));
    }
}

const SYSTEM_PROFILES: &[&str] = &[
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/zshrc",
    "/etc/zsh/zshrc",
    "/etc/zsh/zprofile",
    "/etc/zsh/zshenv",
    "/etc/zsh/zlogin",
    "/etc/environment",
    "/etc/csh.cshrc",
    "/etc/csh.login",
];
const USER_PROFILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".config/fish/config.fish",
    ".xprofile",
    ".xinitrc",
    ".xsessionrc",
];

fn profiles(out: &mut Vec<Entry>, db: &PkgDb, users: &[(String, String)]) {
    let mut files: Vec<String> = SYSTEM_PROFILES.iter().map(|s| s.to_string()).collect();
    for f in dir_files("/etc/profile.d") {
        if db.owns(&f) == Some(false) {
            out.push(Entry::new(Kind::ShellProfile, &f, pr_name(&f), "").floor(
                Severity::Low,
                "profile.d script not owned by any package (runs at every login)",
            ));
        }
        files.push(f);
    }
    for (_, home) in users {
        files.extend(USER_PROFILES.iter().map(|p| format!("{home}/{p}")));
    }
    for f in files {
        if let Some(t) = read_text(&f, CAP) {
            out.extend(pr::profile_entries(&f, &t));
        }
    }
}

fn ssh_keys(out: &mut Vec<Entry>, users: &[(String, String)]) {
    for (user, home) in users {
        for name in ["authorized_keys", "authorized_keys2"] {
            let f = format!("{home}/.ssh/{name}");
            if let Some(t) = read_text(&f, CAP) {
                out.extend(pr::authorized_key_entries(&f, user, &t));
            }
        }
    }
}

fn sudoers(out: &mut Vec<Entry>) {
    let mut files = vec!["/etc/sudoers".to_string()];
    files.extend(
        dir_files("/etc/sudoers.d")
            .into_iter()
            .filter(|f| !f.ends_with("README")),
    );
    for f in files {
        if let Some(t) = read_text(&f, CAP) {
            out.extend(pr::sudoers_entries(&f, &t));
        }
    }
}

fn pam(out: &mut Vec<Entry>, db: &PkgDb) {
    let exists = |m: &str| {
        pr::PAM_DIRS
            .iter()
            .any(|d| Path::new(&format!("{d}{m}")).exists())
    };
    let mut files = dir_files("/etc/pam.d");
    files.push("/etc/pam.conf".into());
    for f in files {
        if let Some(t) = read_text(&f, CAP) {
            out.extend(pr::pam_entries(&f, &t, &exists));
        }
    }
    let mut seen = std::collections::HashSet::new();
    for d in pr::PAM_DIRS {
        let Ok(canon) = fs::canonicalize(d) else {
            continue;
        };
        if !seen.insert(canon) {
            continue;
        }
        for f in dir_files(d).into_iter().filter(|f| f.ends_with(".so")) {
            if db.owns(&f) == Some(false) {
                out.push(Entry::new(Kind::PamModule, &f, pr_name(&f), &f).floor(
                    Severity::High,
                    "PAM module not owned by any package (PAM backdoor)",
                ));
            }
        }
    }
}

fn udev(out: &mut Vec<Entry>) {
    for d in [
        "/etc/udev/rules.d",
        "/run/udev/rules.d",
        "/usr/local/lib/udev/rules.d",
        "/lib/udev/rules.d",
        "/usr/lib/udev/rules.d",
    ] {
        for f in dir_files(d).into_iter().filter(|f| f.ends_with(".rules")) {
            for cmd in pr::parse_udev(&read_text(&f, CAP).unwrap_or_default()) {
                out.push(Entry::new(Kind::Udev, &f, pr_name(&f), cmd));
            }
        }
    }
}

fn xdg(out: &mut Vec<Entry>, users: &[(String, String)]) {
    let mut dirs = vec!["/etc/xdg/autostart".to_string()];
    dirs.extend(users.iter().map(|(_, h)| format!("{h}/.config/autostart")));
    for d in dirs {
        for f in dir_files(&d)
            .into_iter()
            .filter(|f| f.ends_with(".desktop"))
        {
            if let Some(cmd) = pr::parse_desktop(&read_text(&f, CAP).unwrap_or_default()) {
                out.push(Entry::new(Kind::XdgAutostart, &f, pr_name(&f), cmd));
            }
        }
    }
}

fn misc(out: &mut Vec<Entry>) {
    for d in [
        "/etc/modprobe.d",
        "/run/modprobe.d",
        "/usr/local/lib/modprobe.d",
        "/lib/modprobe.d",
        "/usr/lib/modprobe.d",
    ] {
        for f in dir_files(d).into_iter().filter(|f| f.ends_with(".conf")) {
            out.extend(pr::modprobe_entries(
                &f,
                &read_text(&f, CAP).unwrap_or_default(),
            ));
        }
    }
    out.extend(pr::passwd_entries(
        "/etc/passwd",
        &read_text("/etc/passwd", CAP).unwrap_or_default(),
    ));
    for f in dir_files("/etc/apt/apt.conf.d") {
        out.extend(pr::apt_hook_entries(
            &f,
            &read_text(&f, CAP).unwrap_or_default(),
        ));
    }
}

pub fn collect(db: &PkgDb) -> Vec<Entry> {
    let users = homes();
    let user_unit_dirs: Vec<String> = users
        .iter()
        .flat_map(|(_, h)| {
            [
                format!("{h}/.config/systemd/user"),
                format!("{h}/.local/share/systemd/user"),
            ]
        })
        .collect();
    let mut out = Vec::new();
    crontabs(&mut out);
    systemd(&mut out, &user_unit_dirs);
    boot_scripts(&mut out);
    profiles(&mut out, db, &users);
    ssh_keys(&mut out, &users);
    sudoers(&mut out);
    pam(&mut out, db);
    udev(&mut out);
    xdg(&mut out, &users);
    misc(&mut out);
    for e in &mut out {
        if e.owned.is_none() {
            e.owned = db.owns(&e.location);
        }
        if e.mtime.is_none() {
            e.mtime = mtime(&e.location);
        }
    }
    out
}
