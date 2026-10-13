//! Self-contained HTML report (no external resources, works offline on an IR box).

use super::report::Report;

pub fn render(r: &Report, duration_secs: f64) -> String {
    let mut json = serde_json::to_value(r).unwrap_or_default();
    if let Some(o) = json.as_object_mut() {
        o.insert("duration".into(), serde_json::json!(duration_secs));
        o.insert("author".into(), serde_json::json!(crate::brand::AUTHOR));
        o.insert("url".into(), serde_json::json!(crate::brand::URL));
    }
    // Safe inside <script>: no "</script>", no HTML comment openers, no U+2028/2029 surprises.
    let data = json
        .to_string()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    TEMPLATE
        .replace(
            "__TITLE__",
            &format!("{} report - {}", crate::brand::NAME, esc(&r.host)),
        )
        .replace("__DATA__", &data)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const TEMPLATE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  --bg:#0a0e14;--bg2:#0f1520;--panel:#121a26;--line:#1f2a3a;--line2:#2a3a50;
  --text:#c9d4e3;--mute:#7a8aa3;--ink:#eef4ff;--accent:#2ee6c5;--accent2:#7c5cff;
  --crit:#ff3d6e;--high:#ff8a3d;--med:#ffd23d;--low:#3dc8ff;--info:#7a8aa3;
  --mono:ui-monospace,"Cascadia Code","JetBrains Mono",Consolas,monospace;
  --sans:"Segoe UI",system-ui,-apple-system,Roboto,sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 var(--sans)}
body{background:radial-gradient(1200px 500px at 85% -10%,rgba(124,92,255,.12),transparent 60%),radial-gradient(900px 400px at -10% 0%,rgba(46,230,197,.08),transparent 60%),var(--bg)}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1280px;margin:0 auto;padding:28px 20px 60px}
header{display:flex;flex-wrap:wrap;gap:18px;align-items:flex-end;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:20px}
.brand{display:flex;gap:14px;align-items:center}
.logo{width:46px;height:46px;border-radius:12px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:grid;place-items:center;color:#06110f;font:800 20px var(--mono);box-shadow:0 0 30px rgba(46,230,197,.25)}
h1{margin:0;font:700 22px var(--sans);color:var(--ink);letter-spacing:.3px}
.sig{font:12px var(--mono);color:var(--mute);margin-top:2px}
.meta{display:grid;grid-template-columns:auto auto;gap:2px 14px;font:12px var(--mono);color:var(--mute)}
.meta b{color:var(--text);font-weight:500}
.verdict{margin:22px 0 18px;padding:16px 18px;border-radius:12px;border:1px solid var(--line2);display:flex;gap:14px;align-items:center;background:var(--panel)}
.verdict .dot{width:12px;height:12px;border-radius:50%;flex:none;box-shadow:0 0 14px currentColor}
.verdict strong{font-size:16px;color:var(--ink)}
.verdict span{color:var(--mute)}
.cards{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;cursor:pointer;transition:border-color .15s,transform .15s;position:relative;overflow:hidden}
.card:hover{transform:translateY(-2px);border-color:var(--line2)}
.card.on{border-color:currentColor}
.card::before{content:"";position:absolute;inset:0 auto 0 0;width:3px;background:currentColor}
.card b{display:block;font:700 28px var(--mono);color:var(--ink)}
.card span{font:600 11px var(--mono);letter-spacing:.14em;text-transform:uppercase}
.layout{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:18px;margin-top:18px}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.tools input{flex:1;min-width:200px;background:var(--panel);border:1px solid var(--line2);border-radius:10px;padding:9px 12px;color:var(--ink);font:13px var(--mono);outline:none}
.tools input:focus{border-color:var(--accent)}
.chip{background:var(--panel);border:1px solid var(--line2);color:var(--text);border-radius:999px;padding:5px 11px;font:12px var(--mono);cursor:pointer}
.chip.on{background:var(--accent);color:#06110f;border-color:var(--accent)}
.f{background:var(--panel);border:1px solid var(--line);border-radius:12px;margin-bottom:9px;overflow:hidden}
.f>summary{list-style:none;cursor:pointer;padding:12px 14px;display:grid;grid-template-columns:92px minmax(0,1fr) auto;gap:12px;align-items:center}
.f>summary::-webkit-details-marker{display:none}
.f[open]>summary{border-bottom:1px solid var(--line)}
.pill{font:700 11px var(--mono);letter-spacing:.08em;text-align:center;padding:4px 0;border-radius:6px;color:#0a0e14}
.critical .pill{background:var(--crit);color:#fff}.high .pill{background:var(--high)}.medium .pill{background:var(--med)}.low .pill{background:var(--low)}.info .pill{background:var(--info)}
.t{color:var(--ink);font-weight:600;overflow:hidden;text-overflow:ellipsis}
.t small{display:block;font:12px var(--mono);color:var(--mute);font-weight:400;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cat{font:11px var(--mono);color:var(--mute);border:1px solid var(--line2);padding:2px 8px;border-radius:999px}
.body{padding:12px 16px 14px 118px;font:12.5px/1.6 var(--mono);color:var(--text)}
.body .k{color:var(--mute);display:inline-block;min-width:52px}
.body ul{margin:6px 0 0;padding-left:16px}
.body li{word-break:break-all;margin:2px 0}
.mitre{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.mitre a{font:11px var(--mono);border:1px solid rgba(124,92,255,.5);color:#b9a8ff;padding:2px 8px;border-radius:6px}
aside .box{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px;margin-bottom:14px}
aside h3{margin:0 0 10px;font:700 12px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--mute)}
.row{display:flex;justify-content:space-between;gap:8px;font:12px var(--mono);padding:5px 0;border-bottom:1px dashed var(--line);cursor:pointer}
.row:last-child{border-bottom:0}
.row span:first-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar{height:6px;border-radius:3px;background:var(--line);margin-top:3px;overflow:hidden}
.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2))}
.lim{margin:0 0 14px;padding:10px 14px;border-radius:10px;border:1px dashed var(--line2);color:var(--mute);font:12px var(--mono)}
.empty{padding:40px;text-align:center;color:var(--mute);border:1px dashed var(--line2);border-radius:12px}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:var(--mute);font:12px var(--mono);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
@media(max-width:960px){.layout{grid-template-columns:1fr}.cards{grid-template-columns:repeat(3,minmax(0,1fr))}.body{padding-left:16px}}
@media(max-width:560px){.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.f>summary{grid-template-columns:76px minmax(0,1fr)}.cat{display:none}}
@media print{body{background:#fff;color:#000}.tools,aside{display:none}.f{break-inside:avoid}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <div class="logo">ex</div>
      <div><h1 id="name"></h1><div class="sig" id="sig"></div></div>
    </div>
    <div class="meta" id="meta"></div>
  </header>
  <div class="verdict" id="verdict"></div>
  <div id="limits"></div>
  <div class="cards" id="cards"></div>
  <div class="layout">
    <main>
      <div class="tools">
        <input id="q" placeholder="Search title, process, path, pid, ATT&CK id, rule..." autocomplete="off">
      </div>
      <div class="tools" id="cats"></div>
      <div id="list"></div>
    </main>
    <aside>
      <div class="box"><h3>Most suspicious processes</h3><div id="procs"></div></div>
      <div class="box"><h3>ATT&amp;CK techniques</h3><div id="attack"></div></div>
      <div class="box"><h3>Listening sockets</h3><div id="socks"></div></div>
    </aside>
  </div>
  <footer><span id="foot"></span><span id="foot2"></span></footer>
</div>
<script>
(() => {
"use strict";
const R = __DATA__;
const SEV = ["critical","high","medium","low","info"];
const COLOR = {critical:"var(--crit)",high:"var(--high)",medium:"var(--med)",low:"var(--low)",info:"var(--info)"};
const W = {critical:100,high:30,medium:8,low:2,info:0};
const $ = id => document.getElementById(id);
const h = (t, p = {}, ...kids) => { const e = document.createElement(t); for (const [k, v] of Object.entries(p)) { if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v); } for (const c of kids.flat()) if (c != null) e.append(c); return e; };
const state = { sev: new Set(["critical","high","medium","low"]), cat: null, q: "" };

$("name").textContent = R.tool + " v" + R.version + " — threat hunting report";
$("sig").textContent = R.author;
const meta = [["host", R.host], ["kernel", R.kernel], ["started", R.started], ["duration", (R.duration || 0).toFixed(1) + " s"], ["processes", R.processes_scanned], ["root", R.root ? "yes" : "no (partial coverage)"], ["mode", R.deep ? "deep" : "standard"], ["threads", R.stats ? R.stats.threads + (R.stats.soft ? " (soft)" : "") : "-"]];
for (const [k, v] of meta) $("meta").append(h("span", {}, k), h("b", {}, String(v)));

const count = s => R.findings.filter(f => f.severity === s).length;
const worst = SEV.find(s => count(s) > 0 && s !== "info" && s !== "low");
const V = { critical: ["Compromise likely", "Critical indicators of fileless implants, rootkits, tampered binaries or reverse shells were found. Isolate the host and investigate."],
  high: ["Suspicious activity", "High-severity indicators need review before this host can be trusted."],
  medium: ["Needs review", "Unusual but not conclusive findings. Check them against what is installed on this host."] };
const [vt, vd] = V[worst] || ["No significant findings", "Nothing above low severity was detected in this scan."];
$("verdict").append(h("i", { class: "dot", style: "color:" + (worst ? COLOR[worst] : "var(--accent)") + ";background:currentColor" }), h("div", {}, h("strong", {}, vt), h("br"), h("span", {}, vd)));

for (const s of SEV) {
  const c = h("div", { class: "card" + (state.sev.has(s) ? " on" : ""), style: "color:" + COLOR[s], onclick: () => { state.sev.has(s) ? state.sev.delete(s) : state.sev.add(s); c.classList.toggle("on"); draw(); } }, h("b", {}, String(count(s))), h("span", {}, s));
  $("cards").append(c);
}
const cats = [...new Set(R.findings.map(f => f.category))].sort();
const allChip = h("button", { class: "chip on", onclick: () => setCat(null) }, "all");
$("cats").append(allChip);
const chips = {};
for (const c of cats) { chips[c] = h("button", { class: "chip", onclick: () => setCat(c) }, c + " " + R.findings.filter(f => f.category === c).length); $("cats").append(chips[c]); }
function setCat(c) { state.cat = c; allChip.classList.toggle("on", !c); for (const k in chips) chips[k].classList.toggle("on", k === c); draw(); }
$("q").addEventListener("input", e => { state.q = e.target.value.toLowerCase(); draw(); });

const mitreUrl = id => "https://attack.mitre.org/techniques/" + id.replace(".", "/") + "/";
function card(f) {
  const sub = [f.process && (f.process + " [" + f.pid + "]"), f.path].filter(Boolean).join("  ·  ");
  const body = h("div", { class: "body" });
  if (f.process) body.append(h("div", {}, h("span", { class: "k" }, "proc"), f.process + "  pid " + f.pid));
  if (f.path) body.append(h("div", {}, h("span", { class: "k" }, "path"), f.path));
  if (f.address) body.append(h("div", {}, h("span", { class: "k" }, "addr"), f.address));
  if (f.details && f.details.length) body.append(h("ul", {}, f.details.map(d => h("li", {}, d))));
  if (f.mitre && f.mitre.length) body.append(h("div", { class: "mitre" }, f.mitre.map(m => h("a", { href: mitreUrl(m), target: "_blank", rel: "noopener" }, m))));
  return h("details", { class: "f " + f.severity, ...(f.severity === "critical" ? { open: "" } : {}) },
    h("summary", {}, h("span", { class: "pill" }, f.severity.toUpperCase()), h("div", { class: "t" }, f.title, sub ? h("small", {}, sub) : null), h("span", { class: "cat" }, f.category)), body);
}
function match(f) {
  if (!state.sev.has(f.severity)) return false;
  if (state.cat && f.category !== state.cat) return false;
  if (!state.q) return true;
  return JSON.stringify(f).toLowerCase().includes(state.q);
}
function draw() {
  const L = $("list"); L.textContent = "";
  const items = R.findings.filter(match);
  if (!items.length) { L.append(h("div", { class: "empty" }, "No findings match the current filters.")); return; }
  const frag = document.createDocumentFragment();
  for (const f of items.slice(0, 1500)) frag.append(card(f));
  L.append(frag);
  if (items.length > 1500) L.append(h("div", { class: "empty" }, (items.length - 1500) + " more - narrow the filters or use the JSON report."));
}

const score = {};
for (const f of R.findings) if (f.pid != null) { const k = f.process + " [" + f.pid + "]"; score[k] = (score[k] || 0) + W[f.severity]; }
const ranked = Object.entries(score).filter(e => e[1] > 0).sort((a, b) => b[1] - a[1]).slice(0, 12);
const maxS = ranked.length ? ranked[0][1] : 1;
if (!ranked.length) $("procs").append(h("div", { class: "row" }, h("span", {}, "none")));
for (const [k, v] of ranked) $("procs").append(h("div", { onclick: () => { $("q").value = k.split(" [")[1].replace("]", ""); state.q = $("q").value; draw(); } }, h("div", { class: "row" }, h("span", {}, k), h("span", {}, String(v))), h("div", { class: "bar" }, h("i", { style: "width:" + (100 * v / maxS) + "%" }))));

const tech = {};
for (const f of R.findings) if (f.severity !== "info") for (const m of f.mitre || []) tech[m] = (tech[m] || 0) + 1;
const tl = Object.entries(tech).sort((a, b) => b[1] - a[1]);
if (!tl.length) $("attack").append(h("div", { class: "row" }, h("span", {}, "none")));
for (const [m, n] of tl) $("attack").append(h("div", { class: "row", onclick: () => { $("q").value = m; state.q = m.toLowerCase(); draw(); } }, h("a", { href: mitreUrl(m), target: "_blank", rel: "noopener" }, m), h("span", {}, String(n))));

for (const l of R.limitations || []) $("limits").append(h("div", { class: "lim" }, "Limitation: " + l));
const ls = (R.sockets || []).filter(s => s.state === "LISTEN" || s.state === "UNCONN" || s.proto === "packet");
if (!ls.length) $("socks").append(h("div", { class: "row" }, h("span", {}, "none")));
for (const s of ls.slice(0, 200)) $("socks").append(h("div", { class: "row", title: s.exe || "", onclick: () => { if (s.pid != null) { $("q").value = String(s.pid); state.q = $("q").value; draw(); } } }, h("span", {}, s.proto + " " + s.local), h("span", {}, s.process ? s.process + "[" + s.pid + "]" : "?")));
$("foot").textContent = R.tool + " v" + R.version + " · " + R.author;
$("foot2").append(h("a", { href: R.url, target: "_blank", rel: "noopener" }, R.url));
draw();
})();
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::super::report::{Category, Finding, Report, Severity};
    use super::*;

    #[test]
    fn escapes_script_breakout() {
        let mut r = Report {
            tool: "t",
            version: "1",
            host: "h<x>".into(),
            ..Default::default()
        };
        r.sockets.push(crate::core::netrules::SocketRow {
            proto: "tcp".into(),
            local: "</script>".into(),
            ..Default::default()
        });
        r.findings.push(Finding::new(
            Severity::High,
            Category::Process,
            "</script><img src=x onerror=alert(1)>",
        ));
        let html = render(&r, 1.0);
        assert!(!html.contains("</script><img"));
        assert!(html.contains("h&lt;x&gt;"));
        assert_eq!(html.matches("</script>").count(), 1);
        // Top-level `const top` would collide with window.top and kill the whole script.
        assert!(!html.contains("const top "));
        assert!(html.contains("(() => {"));
    }
}
