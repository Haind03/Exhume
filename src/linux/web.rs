//! Web root discovery and the walk that feeds core::webshell and YARA.

use std::fs;
use std::os::unix::fs::MetadataExt;

use super::walk::{par_walk, Walk};
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
    let skip_dir = |_: &str, name: &str| name == "node_modules" || name == ".git";
    let visit = |path: &str, m: &fs::Metadata| {
        lang_of(path).map(|_| {
            (
                path.to_string(),
                m.mtime().max(m.ctime()).max(0) as u64,
                m.size(),
            )
        })
    };
    let (mut out, _) = par_walk(
        roots,
        &Walk {
            max_depth: 24,
            limit: max_files,
            skip_dir: &skip_dir,
            visit: &visit,
        },
    );
    out.truncate(max_files);
    out.sort();
    out
}
