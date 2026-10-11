//! Package database access: file ownership (dpkg, rpm) and integrity verification.

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use md5::{Digest, Md5};
use rayon::prelude::*;

use super::{dir_files, read_text};
use crate::core::paths::usr_aliases;
use crate::core::pkgverify::{
    in_scope, mismatch_finding, parse_md5sums, parse_rpm_verify, rpm_tampered,
};
use crate::core::report::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Dpkg,
    Rpm,
    None,
}

pub struct PkgDb {
    pub manager: Manager,
    owned: HashSet<String>,
}

const DPKG_INFO: &str = "/var/lib/dpkg/info";

/// rpm is an external program; only trusted system locations are used.
fn rpm_bin() -> Option<&'static str> {
    ["/usr/bin/rpm", "/bin/rpm"]
        .into_iter()
        .find(|p| Path::new(p).exists())
}

impl PkgDb {
    pub fn load() -> PkgDb {
        if Path::new(DPKG_INFO).is_dir() {
            let owned: HashSet<String> = dir_files(DPKG_INFO)
                .par_iter()
                .filter(|f| f.ends_with(".list"))
                .flat_map_iter(|f| {
                    read_text(f, 64 << 20)
                        .unwrap_or_default()
                        .lines()
                        .map(String::from)
                        .collect::<Vec<_>>()
                })
                .collect();
            return PkgDb {
                manager: Manager::Dpkg,
                owned,
            };
        }
        if Path::new("/var/lib/rpm").is_dir() {
            if let Some(rpm) = rpm_bin() {
                if let Ok(o) = Command::new(rpm)
                    .args(["-qa", "--qf", "[%{FILENAMES}\n]"])
                    .output()
                {
                    let owned = String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .map(String::from)
                        .collect();
                    return PkgDb {
                        manager: Manager::Rpm,
                        owned,
                    };
                }
            }
        }
        PkgDb {
            manager: Manager::None,
            owned: HashSet::new(),
        }
    }

    /// None when no package database is available.
    pub fn owns(&self, path: &str) -> Option<bool> {
        if self.manager == Manager::None {
            return None;
        }
        Some(usr_aliases(path).iter().any(|p| self.owned.contains(p)))
    }

    pub fn name(&self) -> &'static str {
        match self.manager {
            Manager::Dpkg => "dpkg",
            Manager::Rpm => "rpm",
            Manager::None => "none",
        }
    }
}

fn md5_file(p: &str) -> Option<String> {
    if !fs::symlink_metadata(p).ok()?.is_file() {
        return None;
    }
    let mut f = super::open_regular(p).ok()?;
    let mut h = Md5::new();
    std::io::copy(&mut f, &mut h).ok()?;
    Some(format!("{:x}", h.finalize()))
}

/// dpkg-divert'ed originals (their content legitimately differs from the md5sums entry).
fn diversions() -> HashSet<String> {
    let t = read_text("/var/lib/dpkg/diversions", 4 << 20).unwrap_or_default();
    t.lines().step_by(3).map(String::from).collect()
}

/// Verify packaged files. Returns (findings, files hashed).
pub fn verify(db: &PkgDb, deep: bool) -> (Vec<Finding>, usize) {
    match db.manager {
        Manager::Dpkg => verify_dpkg(deep),
        Manager::Rpm => verify_rpm(deep),
        Manager::None => (Vec::new(), 0),
    }
}

fn verify_dpkg(deep: bool) -> (Vec<Finding>, usize) {
    let div = diversions();
    let mut jobs: Vec<(String, String, String)> = Vec::new();
    for f in dir_files(DPKG_INFO)
        .into_iter()
        .filter(|f| f.ends_with(".md5sums"))
    {
        let pkg = f
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim_end_matches(".md5sums")
            .to_string();
        for (h, p) in parse_md5sums(&read_text(&f, 64 << 20).unwrap_or_default()) {
            if in_scope(&p, deep) && !div.contains(&p) {
                jobs.push((pkg.clone(), p, h));
            }
        }
    }
    let n = jobs.len();
    let findings = jobs
        .par_iter()
        .filter_map(|(pkg, p, h)| {
            let got = md5_file(p)?; // missing files are commonly path-excluded docs: not reported
            (got != *h).then(|| {
                mismatch_finding("dpkg", pkg, p, &format!("md5 expected {h}, found {got}"))
            })
        })
        .collect();
    (findings, n)
}

fn verify_rpm(deep: bool) -> (Vec<Finding>, usize) {
    let Some(rpm) = rpm_bin() else {
        return (Vec::new(), 0);
    };
    let out = if deep {
        Command::new(rpm)
            .args([
                "-Va",
                "--nomtime",
                "--nouser",
                "--nogroup",
                "--nomode",
                "--nordev",
                "--nocaps",
            ])
            .output()
    } else {
        let probes = [
            "/usr/bin/ls",
            "/usr/bin/ps",
            "/usr/bin/netstat",
            "/usr/sbin/ss",
            "/usr/bin/top",
            "/usr/sbin/sshd",
            "/usr/bin/sudo",
            "/usr/bin/su",
            "/usr/bin/login",
            "/usr/bin/passwd",
            "/usr/lib64/libc.so.6",
            "/usr/lib64/security/pam_unix.so",
            "/usr/lib64/libkeyutils.so.1",
            "/usr/bin/find",
            "/usr/bin/lsof",
            "/usr/bin/crontab",
            "/usr/lib/systemd/systemd",
        ];
        let present: Vec<&str> = probes
            .into_iter()
            .filter(|p| Path::new(p).exists())
            .collect();
        Command::new(rpm)
            .args([
                "-Vf",
                "--nomtime",
                "--nouser",
                "--nogroup",
                "--nomode",
                "--nordev",
                "--nocaps",
            ])
            .args(present)
            .output()
    };
    let Ok(o) = out else { return (Vec::new(), 0) };
    let text = String::from_utf8_lossy(&o.stdout);
    let rows = parse_rpm_verify(&text);
    let findings = rows
        .iter()
        .filter(|(flags, cfg, p)| rpm_tampered(flags, *cfg) && in_scope(p, deep))
        .map(|(flags, _, p)| {
            mismatch_finding(
                "rpm",
                "(rpm -V)",
                p,
                &format!("rpm -V flags {flags}: digest differs from package"),
            )
        })
        .collect();
    (findings, rows.len())
}
