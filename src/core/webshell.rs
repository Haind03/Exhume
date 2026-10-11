//! Webshell heuristics for server-side scripts (PHP, JSP, CGI) found under web roots.
//! Each rule pairs a dangerous sink with attacker-controlled input or a packing idiom, so that
//! ordinary application code (which also calls exec() or base64_decode()) stays quiet.

use super::paths::file_name;
use super::procrules::truncate;
use super::report::{Category, Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Php,
    Jsp,
    Cgi,
}

/// Language by extension; `in_cgi` marks files inside a cgi-bin directory.
pub fn lang_of(path: &str) -> Option<Lang> {
    let name = file_name(path).to_ascii_lowercase();
    let ext = name.rsplit('.').next().unwrap_or("");
    match ext {
        "php" | "php3" | "php4" | "php5" | "php7" | "php8" | "phtml" | "pht" | "phar" | "phps"
        | "inc" => Some(Lang::Php),
        "jsp" | "jspx" | "jspf" | "jsw" | "jsv" => Some(Lang::Jsp),
        "cgi" | "pl" | "py" | "sh" | "rb" if path.contains("/cgi-bin/") || ext == "cgi" => {
            Some(Lang::Cgi)
        }
        _ => None,
    }
}

const PHP_SOURCES: &[&str] = &[
    "$_get",
    "$_post",
    "$_request",
    "$_cookie",
    "$_server['http_",
    "$_server[\"http_",
    "php://input",
    "getallheaders(",
    "$_files",
];
const PHP_CODE_SINKS: &[&str] = &[
    "eval(",
    "assert(",
    "create_function(",
    "call_user_func(",
    "call_user_func_array(",
    "register_shutdown_function(",
    "include(",
    "include_once(",
    "require(",
    "require_once(",
    "preg_replace(",
];
const PHP_CMD_SINKS: &[&str] = &[
    "system(",
    "exec(",
    "shell_exec(",
    "passthru(",
    "popen(",
    "proc_open(",
    "pcntl_exec(",
    "`$_",
];
const PHP_DECODERS: &[&str] = &[
    "base64_decode(",
    "gzinflate(",
    "gzuncompress(",
    "gzdecode(",
    "str_rot13(",
    "hex2bin(",
    "convert_uudecode(",
    "strrev(",
    "openssl_decrypt(",
];

/// Strings from well-known webshell families and their default keys.
const FAMILY_MARKERS: &[(&str, &str)] = &[
    ("c99shell", "c99 webshell"),
    ("r57shell", "r57 webshell"),
    ("filesman", "WSO/FilesMan webshell"),
    ("b374k", "b374k webshell"),
    ("e45e329feb5d925b", "Behinder (Rebeyond) default AES key"),
    ("3c6e0b8a9c15224a", "Godzilla default key"),
    ("antsword", "AntSword webshell"),
    ("weevely", "Weevely agent"),
    ("p0wny", "p0wny-shell"),
    ("indoxploit", "IndoXploit webshell"),
    ("alfa team", "ALFA webshell"),
    (
        "@error_reporting(0);@set_time_limit(0)",
        "webshell bootstrap (silence errors, no time limit)",
    ),
    ("phpspy", "PhpSpy webshell"),
    ("china chopper", "China Chopper"),
];

const JSP_SOURCES: &[&str] = &[
    "request.getparameter(",
    "request.getheader(",
    "request.getinputstream(",
    "request.getreader(",
    "request.getattribute(",
];

fn has_any(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| hay.contains(n))
}

/// Lines where a sink and a request source appear together (sink fed by input).
fn sink_with_source(lower: &str, sinks: &[&str], sources: &[&str]) -> Option<String> {
    for line in lower.lines() {
        if has_any(line, sinks) && has_any(line, sources) {
            return Some(truncate(line.trim(), 160));
        }
    }
    None
}

/// `$_POST['a']($_POST['b'])` or `$x = $_GET[..]; $x(...)` style dynamic calls.
fn dynamic_call(lower: &str) -> bool {
    for src in ["$_get[", "$_post[", "$_request[", "$_cookie["] {
        let mut rest = lower;
        while let Some(i) = rest.find(src) {
            let after = &rest[i + src.len()..];
            if let Some(close) = after.find(']') {
                if after[close + 1..].trim_start().starts_with('(') {
                    return true;
                }
            }
            rest = &rest[i + src.len()..];
        }
    }
    false
}

/// Longest run of base64 characters.
fn longest_b64(s: &str) -> usize {
    let (mut best, mut cur) = (0, 0);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

/// Upload and media directories, where server-side scripts do not belong.
fn in_upload_dir(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "/uploads/",
        "/upload/",
        "/images/",
        "/img/",
        "/files/",
        "/media/",
        "/attachments/",
        "/tmp/",
        "/cache/",
        "/static/",
        "/assets/",
    ]
    .iter()
    .any(|d| p.contains(d))
}

pub struct WebFile<'a> {
    pub path: &'a str,
    pub content: &'a str,
    pub mtime: Option<u64>,
    pub now: u64,
}

pub fn analyze(w: &WebFile) -> Option<Finding> {
    let lang = lang_of(w.path)?;
    let lower = w.content.to_ascii_lowercase();
    let mut sev = Severity::Info;
    let mut why: Vec<String> = Vec::new();
    let mut mitre: Vec<&'static str> = vec!["T1505.003"];
    let mut raise = |s: Severity, r: String, sev: &mut Severity| {
        *sev = (*sev).max(s);
        why.push(r);
    };

    match lang {
        Lang::Php => {
            if let Some(l) = sink_with_source(&lower, PHP_CMD_SINKS, PHP_SOURCES) {
                raise(
                    Severity::Critical,
                    format!("OS command built from request input: {l}"),
                    &mut sev,
                );
                mitre.push("T1059.004");
            }
            if let Some(l) = sink_with_source(
                &lower,
                &["eval(", "assert(", "create_function(", "preg_replace("],
                PHP_SOURCES,
            ) {
                raise(
                    Severity::Critical,
                    format!("code evaluation of request input: {l}"),
                    &mut sev,
                );
            } else if let Some(l) = sink_with_source(&lower, PHP_CODE_SINKS, PHP_SOURCES) {
                if !l.contains("include(") && !l.contains("require") || l.contains("php://input") {
                    raise(
                        Severity::High,
                        format!("callback sink fed by request input: {l}"),
                        &mut sev,
                    );
                }
            }
            if dynamic_call(&lower) {
                raise(
                    Severity::Critical,
                    "request parameter called as a function".into(),
                    &mut sev,
                );
            }
            let packed = lower.lines().any(|l| {
                (l.contains("eval(") || l.contains("assert(") || l.contains("create_function("))
                    && PHP_DECODERS.iter().filter(|d| l.contains(*d)).count() >= 1
            });
            if packed {
                raise(
                    Severity::High,
                    "eval of decoded/decompressed data (packed payload)".into(),
                    &mut sev,
                );
                mitre.push("T1027");
            }
            if lower.contains("preg_replace(") && (lower.contains("/e\"") || lower.contains("/e'"))
            {
                raise(
                    Severity::High,
                    "preg_replace with the /e (eval) modifier".into(),
                    &mut sev,
                );
            }
            let chr = lower.matches("chr(").count();
            if chr > 60 {
                raise(
                    Severity::Medium,
                    format!("{chr} chr() calls (character-code obfuscation)"),
                    &mut sev,
                );
                mitre.push("T1027");
            }
            if in_upload_dir(w.path) {
                raise(
                    Severity::Medium,
                    "server-side script inside an upload/media directory".into(),
                    &mut sev,
                );
            }
        }
        Lang::Jsp => {
            let exec = [
                "runtime.getruntime().exec(",
                "new processbuilder(",
                "processbuilder(",
            ];
            if has_any(&lower, &exec) && has_any(&lower, JSP_SOURCES) {
                raise(
                    Severity::Critical,
                    "JSP runs OS commands from request input".into(),
                    &mut sev,
                );
                mitre.push("T1059.004");
            }
            if lower.contains("defineclass")
                && (lower.contains("base64") || lower.contains("cipher.getinstance"))
            {
                raise(
                    Severity::Critical,
                    "JSP defines a class from decoded/decrypted bytes (Behinder/Godzilla loader)"
                        .into(),
                    &mut sev,
                );
                mitre.push("T1620");
            }
            if lower.contains("extends classloader") && has_any(&lower, JSP_SOURCES) {
                raise(
                    Severity::High,
                    "custom ClassLoader fed by request data".into(),
                    &mut sev,
                );
            }
            if in_upload_dir(w.path) {
                raise(
                    Severity::Medium,
                    "JSP inside an upload/media directory".into(),
                    &mut sev,
                );
            }
        }
        Lang::Cgi => {
            let input = [
                "query_string",
                "param(",
                "cgi.fieldstorage",
                "$env{'query",
                "request_method",
                "http_",
            ];
            let exec = [
                "system(",
                "exec(",
                "`",
                "popen(",
                "os.system(",
                "subprocess",
                "qx(",
                "eval(",
            ];
            if has_any(&lower, &input)
                && has_any(&lower, &exec)
                && (lower.contains("cmd") || lower.contains("command") || lower.contains("eval("))
            {
                raise(
                    Severity::High,
                    "CGI script executes commands from request input".into(),
                    &mut sev,
                );
                mitre.push("T1059.004");
            }
        }
    }

    for (m, family) in FAMILY_MARKERS {
        if lower.contains(m) {
            raise(Severity::High, format!("marker of {family}"), &mut sev);
        }
    }
    if longest_b64(w.content) > 2000 && sev >= Severity::Low {
        raise(
            Severity::Medium,
            "embedded base64 blob over 2000 characters".into(),
            &mut sev,
        );
    }
    if sev == Severity::Info {
        return None;
    }
    let hidden = file_name(w.path).starts_with('.');
    if hidden {
        sev = sev.bump();
        why.push("hidden file name".into());
    }
    if w.mtime
        .is_some_and(|m| w.now.saturating_sub(m) < 7 * 86_400)
    {
        sev = sev.bump();
        why.push("modified within the last 7 days".into());
    }
    let mut f = Finding::new(sev, Category::Webshell, "Possible webshell").path(w.path);
    for r in why {
        f = f.detail(r);
    }
    if let Some(m) = w.mtime {
        f = f.detail(format!("modified: {}", super::timefmt::iso8601(m)));
    }
    Some(f.mitre(&mitre))
}

/// Document roots from nginx (`root`, `alias`) and Apache (`DocumentRoot`, `Alias`, `ScriptAlias`) configs.
pub fn parse_web_roots(conf: &str) -> Vec<String> {
    let mut v = Vec::new();
    let stmts = conf
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .flat_map(|l| l.split(['{', '}', ';']));
    for l in stmts.map(str::trim).filter(|l| !l.is_empty()) {
        let mut toks = l.split_whitespace();
        let Some(k) = toks.next() else { continue };
        let k = k.to_ascii_lowercase();
        let val = match k.as_str() {
            "root" | "documentroot" => toks.next(),
            // nginx `alias PATH` vs Apache `Alias URL PATH`
            "alias" | "scriptalias" => {
                let a = toks.next();
                toks.next().or(a)
            }
            _ => None,
        };
        if let Some(p) = val {
            let p = p.trim_matches('"').trim_matches('\'').trim_end_matches('/');
            if p.starts_with('/')
                && !p.contains('$')
                && p.len() > 1
                && !v.iter().any(|x: &String| x == p)
            {
                v.push(p.to_string());
            }
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_760_000_000;

    fn run(path: &str, c: &str) -> Option<Finding> {
        analyze(&WebFile {
            path,
            content: c,
            mtime: Some(1),
            now: NOW,
        })
    }

    #[test]
    fn php_one_liners() {
        let cases = [
            "<?php @eval($_POST['cmd']); ?>",
            "<?php system($_GET['c']); ?>",
            "<?php $_POST['a']($_POST['b']); ?>",
            "<?php echo `$_GET[x]`; ?>",
            "<?php assert($_REQUEST['z']);",
        ];
        for c in cases {
            let f = run("/var/www/html/x.php", c).unwrap_or_else(|| panic!("{c}"));
            assert_eq!(f.severity, Severity::Critical, "{c}");
            assert!(f.mitre.contains(&"T1505.003"));
        }
    }

    #[test]
    fn php_packed_and_family() {
        let f = run(
            "/var/www/html/a.php",
            "<?php eval(gzinflate(base64_decode('7X1rcxs3sv...')));",
        )
        .unwrap();
        assert_eq!(f.severity, Severity::High);
        let f = run(
            "/var/www/html/b.php",
            "<?php @error_reporting(0);@set_time_limit(0); $x=1;",
        )
        .unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn php_benign() {
        for c in [
            "<?php require_once __DIR__ . '/vendor/autoload.php'; $app = new App(); $app->run();",
            "<?php $id = intval($_GET['id']); echo htmlspecialchars($row['name']);",
            "<?php $data = base64_decode($token); return json_decode($data);",
            "<?php exec('/usr/bin/convert ' . escapeshellarg($file));",
            "<?php $ids = array_map('intval', $_GET['ids']);",
        ] {
            assert!(run("/var/www/html/index.php", c).is_none(), "{c}");
        }
    }

    #[test]
    fn upload_dir_and_bumps() {
        let f = run(
            "/var/www/html/wp-content/uploads/2025/x.php",
            "<?php echo 1;",
        )
        .unwrap();
        assert_eq!(f.severity, Severity::Medium);
        let f = analyze(&WebFile {
            path: "/var/www/html/.x.php",
            content: "<?php system($_GET['c']);",
            mtime: Some(NOW - 10),
            now: NOW,
        })
        .unwrap();
        assert_eq!(f.severity, Severity::Critical);
        let f = analyze(&WebFile {
            path: "/var/www/html/up/.a.php",
            content: "<?php eval(base64_decode($x));",
            mtime: Some(1),
            now: NOW,
        })
        .unwrap();
        assert_eq!(f.severity, Severity::Critical, "hidden bumps High");
    }

    #[test]
    fn jsp() {
        let c = "<% String c = request.getParameter(\"cmd\"); Process p = Runtime.getRuntime().exec(c); %>";
        assert_eq!(
            run("/opt/tomcat/webapps/ROOT/x.jsp", c).unwrap().severity,
            Severity::Critical
        );
        let b = "<%@page import=\"java.util.*,javax.crypto.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(\"e45e329feb5d925b\".getBytes(),\"AES\"));%>";
        let f = run("/opt/tomcat/webapps/ROOT/shell.jsp", b).unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.details.iter().any(|d| d.contains("Behinder")));
        assert!(run(
            "/opt/tomcat/webapps/ROOT/index.jsp",
            "<html><%= new java.util.Date() %></html>"
        )
        .is_none());
    }

    #[test]
    fn cgi_and_langs() {
        let c = "#!/usr/bin/perl\nuse CGI; my $q=CGI->new; my $cmd=$q->param('cmd'); print `$cmd`;";
        assert_eq!(
            run("/usr/lib/cgi-bin/t.pl", c).unwrap().severity,
            Severity::High
        );
        assert_eq!(lang_of("/var/www/a.PHP5"), Some(Lang::Php));
        assert_eq!(lang_of("/var/www/a.pl"), None);
        assert_eq!(lang_of("/var/www/cgi-bin/a.pl"), Some(Lang::Cgi));
        assert_eq!(lang_of("/var/www/a.js"), None);
    }

    #[test]
    fn roots() {
        let nginx = "server {\n  root /srv/site/public;\n  location /static/ { alias /srv/static/; }\n  # root /old;\n  root $document_root;\n}\n";
        assert_eq!(
            parse_web_roots(nginx),
            vec!["/srv/site/public", "/srv/static"]
        );
        let apache = "<VirtualHost *:80>\n DocumentRoot \"/var/www/app\"\n ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/\n</VirtualHost>\n";
        assert_eq!(
            parse_web_roots(apache),
            vec!["/var/www/app", "/usr/lib/cgi-bin"]
        );
    }
}
