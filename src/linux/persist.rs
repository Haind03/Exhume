//! Collects autostart entries from the filesystem. Parsing and scoring live in core::persistrules.

use std::fs;
use std::path::Path;

use super::pkg::PkgDb;
use super::{dir_files, homes, mtime, read_text};
use crate::core::persistext as px;
use crate::core::persistrules::{self as pr, Entry, Kind};
use crate::core::procrules::cmdline_hits;
use crate::core::report::Severity;

const CAP: usize = 1 << 20;

/// Script files (cron.daily, init.d, rc.local, update-motd.d): content lines run through the
/// command-line rules.
fn script_entry(kind: Kind, path: &str) -> Option<Entry> {
    let text = read_text(path, CAP)?;
    let mut e = Entry::new(kind, path, pr_name(path), path);
    // Compiled programs (ELF generators, binary hooks) are listed but not read as shell text:
    // their string tables would look like command lines.
    if text.contains('\0') {
        return Some(e);
    }
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
            // Generators run as root at every boot and daemon-reload: read the script itself.
            out.push(
                script_entry(Kind::SystemdGenerator, &f)
                    .unwrap_or_else(|| Entry::new(Kind::SystemdGenerator, &f, pr_name(&f), &f)),
            );
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
            let text = read_text(&f, CAP).unwrap_or_default();
            for cmd in pr::parse_udev(&text) {
                out.push(Entry::new(Kind::Udev, &f, pr_name(&f), cmd));
            }
            // Rules that start a systemd unit run whatever that unit's ExecStart says.
            for unit in pr::parse_udev_systemd_wants(&text) {
                let exec = UNIT_DIRS
                    .iter()
                    .map(|d| format!("{d}/{unit}"))
                    .find(|p| Path::new(p).is_file())
                    .and_then(|p| read_text(&p, CAP))
                    .map(|t| {
                        pr::parse_unit(&t)
                            .into_iter()
                            .filter(|(k, _)| k.starts_with("Exec"))
                            .map(|(_, v)| v)
                            .collect::<Vec<_>>()
                            .join("; ")
                    })
                    .unwrap_or_default();
                let mut e = Entry::new(
                    Kind::Udev,
                    &f,
                    format!("{} starts {unit}", pr_name(&f)),
                    exec,
                );
                e.notes.push(format!(
                    "ENV{{SYSTEMD_WANTS}} starts {unit} whenever the device event fires"
                ));
                out.push(e);
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

/// Recursive regular files under `dir` (symlinks not followed), sorted.
fn tree_files(dir: &str, max_depth: u32) -> Vec<String> {
    use super::walk::{par_walk, Walk};
    let visit = |p: &str, _: &fs::Metadata| Some(p.to_string());
    let (mut v, _) = par_walk(
        &[dir.to_string()],
        &Walk {
            max_depth,
            limit: 50_000,
            skip_dir: &|_, _| false,
            visit: &visit,
        },
    );
    v.sort();
    v
}

/// `prefix*suffix` style expansion for one path component (python3.*, etc.).
fn glob_dirs(parent: &str, prefix: &str, rest: &str) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(parent)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
                .map(|e| format!("{}/{rest}", e.path().to_string_lossy()))
                .filter(|p| Path::new(p).is_dir())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn ssh_extra(out: &mut Vec<Entry>, users: &[(String, String)]) {
    for f in ["/etc/ssh/sshrc".to_string()]
        .into_iter()
        .chain(users.iter().map(|(_, h)| format!("{h}/.ssh/rc")))
    {
        if let Some(e) = script_entry(Kind::SshRc, &f) {
            out.push(e.floor(
                Severity::Medium,
                "runs on every SSH login (rarely used legitimately)",
            ));
        }
    }
    let mut confs = vec!["/etc/ssh/sshd_config".to_string()];
    confs.extend(
        dir_files("/etc/ssh/sshd_config.d")
            .into_iter()
            .filter(|f| f.ends_with(".conf")),
    );
    for f in confs {
        out.extend(px::sshd_config_entries(
            &f,
            &read_text(&f, CAP).unwrap_or_default(),
        ));
    }
    for (user, home) in users {
        let f = format!("{home}/.ssh/environment");
        if let Some(t) = read_text(&f, CAP) {
            out.extend(px::ssh_environment_entries(&f, user, &t));
        }
    }
}

fn git(out: &mut Vec<Entry>, users: &[(String, String)]) {
    let mut confs = vec!["/etc/gitconfig".to_string()];
    for (_, h) in users {
        confs.push(format!("{h}/.gitconfig"));
        confs.push(format!("{h}/.config/git/config"));
    }
    for f in confs {
        if let Some(t) = read_text(&f, CAP) {
            out.extend(px::gitconfig_entries(&f, &t));
        }
    }
    // Hooks of repositories in homes and service directories (shallow: repos live near the top).
    use super::walk::{par_walk, Walk};
    let mut roots: Vec<String> = users.iter().map(|(_, h)| h.clone()).collect();
    roots.extend(
        ["/srv", "/opt", "/var/www", "/root"]
            .iter()
            .map(|s| s.to_string()),
    );
    roots.sort();
    roots.dedup();
    let visit = |p: &str, m: &fs::Metadata| {
        use std::os::unix::fs::PermissionsExt;
        (p.contains("/.git/hooks/")
            && !p.ends_with(".sample")
            && m.permissions().mode() & 0o111 != 0)
            .then(|| p.to_string())
    };
    let skip = |_: &str, n: &str| {
        matches!(
            n,
            "node_modules"
                | ".cache"
                | ".cargo"
                | ".rustup"
                | "target"
                | ".npm"
                | ".local"
                | "objects"
                | "refs"
                | "logs"
        )
    };
    let (hooks, _) = par_walk(
        &roots,
        &Walk {
            max_depth: 6,
            limit: 5_000,
            skip_dir: &skip,
            visit: &visit,
        },
    );
    for h in hooks {
        out.extend(script_entry(Kind::GitHook, &h));
    }
}

fn python_startup(out: &mut Vec<Entry>, users: &[(String, String)]) {
    let mut dirs = Vec::new();
    for base in ["/usr/lib", "/usr/local/lib", "/usr/lib64"] {
        for sub in ["site-packages", "dist-packages"] {
            dirs.extend(glob_dirs(base, "python3", sub));
        }
    }
    dirs.push("/usr/lib/python3/dist-packages".into());
    for (_, h) in users {
        dirs.extend(glob_dirs(
            &format!("{h}/.local/lib"),
            "python3",
            "site-packages",
        ));
    }
    dirs.sort();
    dirs.dedup();
    for d in dirs {
        for f in dir_files(&d).into_iter().filter(|f| f.ends_with(".pth")) {
            out.extend(px::pth_entries(&f, &read_text(&f, CAP).unwrap_or_default()));
        }
    }
}

fn system_hooks(out: &mut Vec<Entry>) {
    for f in tree_files("/etc/NetworkManager/dispatcher.d", 3) {
        out.extend(script_entry(Kind::NetworkDispatcher, &f));
    }
    for d in [
        "/usr/share/dbus-1/system-services",
        "/usr/local/share/dbus-1/system-services",
        "/etc/dbus-1/system-services",
        "/usr/share/dbus-1/services",
    ] {
        for f in dir_files(d).into_iter().filter(|f| f.ends_with(".service")) {
            if let Some(exec) = px::dbus_service_exec(&read_text(&f, CAP).unwrap_or_default()) {
                out.push(Entry::new(Kind::DbusService, &f, pr_name(&f), exec));
            }
        }
    }
    let mut pk = dir_files("/etc/polkit-1/rules.d");
    pk.extend(dir_files("/usr/share/polkit-1/rules.d"));
    pk.extend(tree_files("/etc/polkit-1/localauthority", 3));
    pk.extend(tree_files("/var/lib/polkit-1/localauthority", 3));
    for f in pk
        .into_iter()
        .filter(|f| f.ends_with(".rules") || f.ends_with(".pkla"))
    {
        out.extend(px::polkit_entries(
            &f,
            &read_text(&f, CAP).unwrap_or_default(),
        ));
    }
    let mut grub = vec!["/etc/default/grub".to_string()];
    grub.extend(dir_files("/etc/default/grub.d"));
    for f in grub {
        out.extend(px::grub_entries(
            &f,
            &read_text(&f, CAP).unwrap_or_default(),
        ));
    }
    for d in [
        "/etc/initramfs-tools/hooks",
        "/etc/initramfs-tools/scripts",
        "/usr/share/initramfs-tools/hooks",
        "/usr/lib/dracut/modules.d",
        "/etc/dracut.conf.d",
    ] {
        for f in tree_files(d, 4) {
            out.extend(script_entry(Kind::Initramfs, &f));
        }
    }
    let mut ld = vec!["/etc/ld.so.conf".to_string()];
    ld.extend(dir_files("/etc/ld.so.conf.d"));
    for f in ld {
        out.extend(px::ld_conf_entries(
            &f,
            &read_text(&f, CAP).unwrap_or_default(),
        ));
    }
    // yum/dnf plugins are python modules loaded on every package operation.
    let mut plugin_dirs = vec![
        "/usr/lib/yum-plugins".to_string(),
        "/usr/share/yum-plugins".to_string(),
    ];
    for base in ["/usr/lib", "/usr/lib64"] {
        plugin_dirs.extend(glob_dirs(base, "python3", "site-packages/dnf-plugins"));
    }
    for d in plugin_dirs {
        for f in dir_files(&d).into_iter().filter(|f| f.ends_with(".py")) {
            out.extend(
                script_entry(Kind::AptHook, &f)
                    .or_else(|| Some(Entry::new(Kind::AptHook, &f, pr_name(&f), &f))),
            );
        }
    }
}

fn web_modules(out: &mut Vec<Entry>, db: &PkgDb) {
    let mut confs = Vec::new();
    for d in [
        "/etc/apache2/mods-enabled",
        "/etc/apache2",
        "/etc/httpd/conf.modules.d",
        "/etc/httpd/conf",
        "/etc/nginx",
        "/etc/nginx/modules-enabled",
        "/etc/nginx/conf.d",
    ] {
        confs.extend(
            dir_files(d)
                .into_iter()
                .filter(|f| f.ends_with(".load") || f.ends_with(".conf")),
        );
    }
    for conf in confs {
        let text = read_text(&conf, CAP).unwrap_or_default();
        for m in px::webserver_modules(&text) {
            let path = if m.starts_with('/') {
                m.clone()
            } else if conf.starts_with("/etc/httpd") {
                format!("/etc/httpd/{m}")
            } else {
                format!("/usr/lib/apache2/{m}")
            };
            let mut e = Entry::new(Kind::WebServerModule, &conf, pr_name(&path), &path);
            e.owned = db.owns(&path);
            if e.owned == Some(false) {
                e = e.floor(
                    Severity::High,
                    "module loaded into the web server is not owned by any package",
                );
            }
            out.push(e);
        }
    }
}

/// Follow entries to the script they run and read it: a systemd ExecStart, a D-Bus Exec, a cron
/// command or a generator pointing at `/usr/local/bin/x.sh` is only as clean as that script.
fn inspect_target_scripts(out: &mut [Entry]) {
    for e in out.iter_mut() {
        if matches!(
            e.kind,
            Kind::AuthorizedKey
                | Kind::Sudoers
                | Kind::Account
                | Kind::Capability
                | Kind::SshdConfig
                | Kind::GitConfig
                | Kind::Polkit
                | Kind::Bootloader
                | Kind::LdConfig
        ) {
            continue;
        }
        let target = if e.kind == Kind::Pam {
            // pam_exec.so [options] /path/program: the program runs on every authentication.
            e.command
                .split_whitespace()
                .find(|t| t.starts_with('/') && !t.ends_with(".so"))
                .map(String::from)
        } else if e.command.starts_with('/') && !e.command.contains(' ') {
            Some(e.command.clone())
        } else {
            crate::core::persistrules::command_target(&e.command)
        };
        let Some(t) = target else { continue };
        if t == e.location {
            continue; // already read as a script
        }
        let Some(text) = read_text(&t, 256 << 10) else {
            continue;
        };
        if !text.starts_with("#!") {
            continue;
        }
        for (n, why) in px::script_hits(&text) {
            let sev = crate::core::procrules::cmdline_hits(text.lines().nth(n - 1).unwrap_or(""))
                .iter()
                .map(|h| h.severity)
                .max()
                .unwrap_or(Severity::Medium);
            e.floor = e.floor.max(sev);
            e.notes.push(format!("target script {t} line {n}: {why}"));
        }
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
    ssh_extra(&mut out, &users);
    git(&mut out, &users);
    python_startup(&mut out, &users);
    system_hooks(&mut out);
    web_modules(&mut out, db);
    inspect_target_scripts(&mut out);
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
