//! Web root discovery and the walk that feeds core::webshell and YARA.

use std::fs;
use std::os::unix::fs::MetadataExt;

use super::{dir_files, read_text};
use crate::core::webshell::{lang_of, parse_web_roots};

const DEFAULT_ROOTS: &[&str] = &[
    "/var/www",
    "/srv/www",
    "/srv/http",
    "/usr/share/nginx/html",
    "/usr/local/nginx/html",
    "/usr/local/apache2/htdocs",
    "/opt/lampp/htdocs",
    "/usr/lib/cgi-bin",
    "/var/lib/tomcat9/webapps",
    "/var/lib/tomcat10/webapps",
    "/var/lib/tomcat/webapps",
    "/usr/share/tomcat/webapps",
    "/opt/tomcat/webapps",
    "/usr/local/tomcat/webapps",
    "/var/lib/jetty9/webapps",
];

const CONF_DIRS: &[&str] = &[
    "/etc/nginx",
    "/etc/nginx/conf.d",
    "/etc/nginx/sites-enabled",
    "/etc/apache2",
    "/etc/apache2/sites-enabled",
    "/etc/apache2/conf-enabled",
    "/etc/httpd/conf",
    "/etc/httpd/conf.d",
    "/etc/lighttpd",
    "/usr/local/nginx/conf",
    "/usr/local/apache2/conf",
];

pub fn roots(users: &[(String, String)]) -> Vec<String> {
    let mut v: Vec<String> = DEFAULT_ROOTS.iter().map(|s| s.to_string()).collect();
    for d in CONF_DIRS {
        for f in dir_files(d) {
            if let Some(t) = read_text(&f, 1 << 20) {
                v.extend(parse_web_roots(&t));
            }
        }
    }
    v.extend(users.iter().map(|(_, h)| format!("{h}/public_html")));
    let mut canon: Vec<String> = v
        .iter()
        .filter_map(|r| fs::canonicalize(r).ok())
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|p| p != "/")
        .collect();
    canon.sort();
    canon.dedup();
    let all = canon.clone();
    canon.retain(|r| {
        !all.iter()
            .any(|o| o != r && r.starts_with(&format!("{o}/")))
    });
    canon
}

/// Server-side script files under the roots: (path, mtime, size).
pub fn scripts(roots: &[String], max_files: usize) -> Vec<(String, u64, u64)> {
    let mut out = Vec::new();
    let mut stack: Vec<(String, u32)> = roots.iter().map(|r| (r.clone(), 0)).collect();
    while let Some((dir, depth)) = stack.pop() {
        if depth > 24 || out.len() >= max_files {
            continue;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let path = e.path().to_string_lossy().into_owned();
            let Ok(m) = fs::symlink_metadata(&path) else {
                continue;
            };
            if m.is_dir() {
                let n = e.file_name();
                if n != "node_modules" && n != ".git" {
                    stack.push((path, depth + 1));
                }
            } else if m.is_file() && lang_of(&path).is_some() {
                out.push((path, m.mtime().max(m.ctime()).max(0) as u64, m.size()));
            }
        }
    }
    out
}
