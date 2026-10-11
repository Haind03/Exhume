//! Exhume - live Linux threat hunting.
//! HaiND from the Post and Telecommunication Institute of Technology.

mod brand;
mod core;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(feature = "yara")]
mod rules;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("{} only runs on Linux.", brand::NAME);
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(app::run());
}

#[cfg(target_os = "linux")]
mod app {
    use std::collections::HashMap;
    use std::io::{IsTerminal, Write};
    use std::time::Instant;

    use clap::Parser;
    use rayon::prelude::*;
    use sha2::{Digest, Sha256};

    use crate::brand;
    use crate::core::report::{Category, Finding, Report, Severity};
    use crate::core::{
        injectrules, memrules, netrules, persistrules, procrules, timefmt, webshell, ProcInfo,
    };
    use crate::linux::{self, mem, net, persist, pkg, procs, rootkit, suid, web};

    #[derive(Parser, Debug)]
    #[command(
        name = "exhume",
        version,
        about = "Live Linux threat hunting: fileless implants, injected code, rootkits, stealthy persistence and backdoor sockets.",
        after_help = "Exit codes: 0 = nothing High or Critical, 2 = High/Critical findings, 1 = error.\nRun as root for full coverage. Read-only: nothing on the host is modified.\nby HaiND from the Post and Telecommunication Institute of Technology"
    )]
    struct Args {
        /// Write the JSON report to FILE ("-" or no value = stdout, which silences the console report)
        #[arg(long, value_name = "FILE", num_args = 0..=1, default_missing_value = "-")]
        json: Option<String>,
        /// Write a self-contained offline HTML report to FILE
        #[arg(long, value_name = "FILE")]
        html: Option<String>,
        /// Hide findings below this level: info, low, medium, high, critical
        #[arg(long, value_name = "LEVEL", default_value = "low", value_parser = parse_sev)]
        min_severity: Severity,
        /// Slower, wider sweep: all anonymous regions, whole-filesystem SUID walk, every packaged file hashed, YARA on all process images
        #[arg(long)]
        deep: bool,
        /// Disable ANSI colours
        #[arg(long)]
        no_color: bool,
        /// Skip YARA scanning
        #[arg(long)]
        no_yara: bool,
        /// Extra YARA rule file(s) to load alongside the embedded set
        #[arg(long = "rules", value_name = "FILE")]
        extra_rules: Vec<String>,
        /// Skip the kill(pid, 0) brute force over the whole PID space
        #[arg(long)]
        no_pid_bruteforce: bool,
        /// No progress messages on stderr
        #[arg(short, long)]
        quiet: bool,
    }

    fn parse_sev(s: &str) -> Result<Severity, String> {
        Severity::parse(s)
            .ok_or_else(|| format!("unknown severity '{s}' (info, low, medium, high, critical)"))
    }

    struct Ui {
        quiet: bool,
        color: bool,
        t0: Instant,
    }

    impl Ui {
        fn step(&self, msg: &str) {
            if !self.quiet {
                let (d, r) = if self.color {
                    ("\x1b[90m", "\x1b[0m")
                } else {
                    ("", "")
                };
                eprintln!("{d}[{:>6.1}s]{r} {msg}", self.t0.elapsed().as_secs_f64());
            }
        }
    }

    /// YARA work list gathered while the other modules run.
    #[derive(Default)]
    struct Targets {
        mem: Vec<(u32, String, u64, u64, String)>,
        files: Vec<(String, String)>,
    }

    pub fn run() -> i32 {
        let args = Args::parse();
        let t0 = Instant::now();
        let color = !args.no_color
            && std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none();
        let json_stdout = args.json.as_deref() == Some("-");
        let ui = Ui {
            quiet: args.quiet,
            color: color && std::io::stderr().is_terminal(),
            t0,
        };
        if !args.quiet {
            eprintln!("{}", brand::BANNER);
            eprintln!(
                "  {} v{}  //  {}\n  {}\n",
                brand::NAME,
                brand::VERSION,
                brand::TAGLINE,
                brand::AUTHOR
            );
        }

        let root = linux::is_root();
        let started = linux::now();
        let mut report = Report {
            tool: brand::NAME,
            version: brand::VERSION,
            host: linux::hostname(),
            kernel: linux::kernel(),
            started: timefmt::iso8601(started),
            root,
            deep: args.deep,
            ..Default::default()
        };
        if !root {
            report.limitations.push("not running as root: other users' processes, memory, environ, kernel symbol addresses, eBPF and some persistence files are not visible".into());
        }
        let mut findings: Vec<Finding> = Vec::new();
        let mut targets = Targets::default();

        // ---- processes
        ui.step("enumerating processes");
        let self_pid = std::process::id();
        let pids = linux::list_pids();
        let procs: Vec<ProcInfo> = pids
            .par_iter()
            .filter(|&&p| p != self_pid)
            .filter_map(|&p| procs::collect(p))
            .collect();
        report.processes_scanned = procs.len();
        let restricted = procs.iter().filter(|p| p.restricted && !p.kthread).count();
        if restricted > 0 {
            report.limitations.push(format!(
                "{restricted} processes only partially readable (permission denied)"
            ));
        }
        let by_pid: HashMap<u32, &ProcInfo> = procs.iter().map(|p| (p.pid, p)).collect();

        ui.step("mapping sockets to processes");
        report.sockets = net::sockets(&procs);
        let inet = net::inet_map(&report.sockets);

        ui.step(&format!(
            "scanning {} processes (process, injection, memory)",
            procs.len()
        ));
        let per_proc: Vec<(Vec<Finding>, Targets)> = procs
            .par_iter()
            .filter(|p| !p.kthread || procrules::looks_like_kthread(&p.comm))
            .map(|p| scan_process(p, &by_pid, &inet, args.deep))
            .collect();
        for (f, t) in per_proc {
            findings.extend(f);
            targets.mem.extend(t.mem);
            targets.files.extend(t.files);
        }

        // ---- system-wide injection
        if let Some(t) = linux::read_text("/etc/ld.so.preload", 1 << 20) {
            findings.extend(injectrules::ld_so_preload_findings(
                "/etc/ld.so.preload",
                &t,
                &|l| std::path::Path::new(l).exists(),
            ));
            for l in injectrules::parse_ld_so_preload(&t) {
                targets.files.push((l, "/etc/ld.so.preload library".into()));
            }
        }

        // ---- rootkit cross-views
        if !args.no_pid_bruteforce {
            ui.step("cross-checking /proc against kill(pid, 0) over the PID space");
            findings.extend(rootkit::hidden_processes());
        }
        ui.step("cross-checking kernel modules, taint and eBPF");
        findings.extend(rootkit::modules(root));
        findings.extend(rootkit::taint());
        match rootkit::bpf_programs() {
            Ok(p) => findings.extend(crate::core::rootkit::bpf_findings(&p)),
            Err(e) if rootkit::bpf_available() => report
                .limitations
                .push(format!("eBPF programs not enumerated: {e}")),
            Err(_) => {}
        }

        // ---- persistence
        ui.step("loading package database");
        let db = pkg::PkgDb::load();
        if db.manager == pkg::Manager::None {
            report.limitations.push(
                "no dpkg/rpm database: package ownership and integrity checks skipped".into(),
            );
        }
        ui.step("collecting persistence mechanisms");
        let now = linux::now();
        let entries = persist::collect(&db);
        let (suids, files_seen) = suid::sweep(args.deep, &|p| db.owns(p));
        ui.step(&format!("swept {files_seen} files for SUID/SGID bits"));
        for e in entries.iter().chain(suids.iter()) {
            if let Some(f) = persistrules::score(e, now) {
                if f.severity >= Severity::Low {
                    if let Some(t) = persist_target(e) {
                        targets
                            .files
                            .push((t, format!("{} target", e.kind.label())));
                    }
                }
                findings.push(f);
            }
        }

        // ---- webshells
        let roots = web::roots(&linux::homes());
        let scripts = web::scripts(&roots, if args.deep { usize::MAX } else { 50_000 });
        ui.step(&format!(
            "hunting webshells: {} server-side scripts under {} web roots",
            scripts.len(),
            roots.len()
        ));
        findings.extend(
            scripts
                .par_iter()
                .filter_map(|(path, mtime, _)| {
                    let text = linux::read_text(path, 2 << 20)?;
                    webshell::analyze(&webshell::WebFile {
                        path,
                        content: &text,
                        mtime: Some(*mtime),
                        now,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let yara_web = if args.deep { usize::MAX } else { 20_000 };
        targets.files.extend(
            scripts
                .into_iter()
                .filter(|(_, _, size)| *size <= 4 << 20)
                .take(yara_web)
                .map(|(p, _, _)| (p, "web script".to_string())),
        );

        // ---- package integrity
        ui.step(&format!("verifying packaged files ({})", db.name()));
        let (pf, hashed) = pkg::verify(&db, args.deep);
        if db.manager != pkg::Manager::None {
            ui.step(&format!("verified {hashed} packaged files"));
        }
        findings.extend(pf);

        // ---- network
        findings.extend(netrules::analyze(&report.sockets, root));

        // ---- YARA
        #[cfg(feature = "yara")]
        if !args.no_yara {
            yara_phase(&ui, &args, &mut report, &mut findings, targets);
        }
        #[cfg(not(feature = "yara"))]
        {
            let _ = targets;
            report
                .limitations
                .push("built without the yara feature".into());
        }

        // ---- IR enrichment and output
        enrich_hashes(&mut findings, args.deep);
        let denied = linux::DENIED.load(std::sync::atomic::Ordering::Relaxed);
        if denied > 0 && !root {
            report.limitations.push(format!(
                "{denied} reads were refused with permission denied"
            ));
        }
        report.findings = findings;
        report.sort();
        dedup(&mut report.findings);
        let code = report.exit_code();
        report.retain_min(args.min_severity);
        let secs = t0.elapsed().as_secs_f64();
        ui.step(&format!("done in {secs:.1}s"));

        if !json_stdout {
            report.print(color);
        }
        if let Some(path) = &args.json {
            let text = serde_json::to_string_pretty(&report).unwrap_or_default();
            if path == "-" {
                let _ = writeln!(std::io::stdout(), "{text}");
            } else if let Err(e) = std::fs::write(path, text) {
                eprintln!("cannot write {path}: {e}");
                return 1;
            } else {
                ui.step(&format!("JSON report written to {path}"));
            }
        }
        if let Some(path) = &args.html {
            if let Err(e) = std::fs::write(path, crate::core::html::render(&report, secs)) {
                eprintln!("cannot write {path}: {e}");
                return 1;
            }
            ui.step(&format!("HTML report written to {path}"));
        }
        code
    }

    fn scan_process(
        p: &ProcInfo,
        by_pid: &HashMap<u32, &ProcInfo>,
        inet: &HashMap<u64, String>,
        deep: bool,
    ) -> (Vec<Finding>, Targets) {
        let mut out = Vec::new();
        let mut t = Targets::default();
        let parent = by_pid.get(&p.ppid).copied();
        out.extend(procrules::analyze(p, &procrules::ProcCtx { parent, inet }));
        if p.kthread {
            return (out, t);
        }
        out.extend(injectrules::env_findings(p));
        let tracer = by_pid.get(&p.tracer_pid).map(|t| t.comm.as_str());
        out.extend(injectrules::tracer_finding(p, tracer));

        if let Some(maps) = mem::maps(p.pid) {
            let memf = mem::open_mem(p.pid);
            let peeks = mem::peeks(memf.as_ref(), &maps, deep);
            let mf = memrules::analyze(&memrules::MemView {
                pid: p.pid,
                name: p.name(),
                maps: &maps,
                peeks: &peeks,
                deep,
            });
            // Memory regions that earned a finding (and in deep mode every candidate) go to YARA.
            let flagged: Vec<u64> = mf
                .iter()
                .filter_map(|f| f.address.as_deref())
                .filter_map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok())
                .collect();
            let jit = memrules::is_jit(p.name(), &maps);
            for m in memrules::peek_candidates(&maps, deep) {
                // Data-only heap regions are left out even in deep mode: any process that holds
                // rule text or AV signatures in memory would match them.
                if flagged.contains(&m.start)
                    || (deep
                        && !jit
                        && (m.exec || crate::core::paths::memfd_name(&m.path).is_some()))
                    || memrules::elf_header(peeks.get(&m.start).map(Vec::as_slice).unwrap_or(&[]))
                        .is_some()
                {
                    t.mem.push((
                        p.pid,
                        p.name().to_string(),
                        m.start,
                        m.size(),
                        format!(
                            "{} {}",
                            m.perms(),
                            if m.path.is_empty() { "[anon]" } else { &m.path }
                        ),
                    ));
                }
            }
            out.extend(mf);
        }

        // The process image goes to YARA when the process itself looks wrong (works even if deleted).
        let suspicious = out.iter().any(|f| f.severity >= Severity::Medium);
        if (suspicious || deep) && p.exe.is_some() {
            t.files.push((
                format!("/proc/{}/exe", p.pid),
                format!("image of {} [pid {}]", p.name(), p.pid),
            ));
        }
        (out, t)
    }

    fn persist_target(e: &persistrules::Entry) -> Option<String> {
        use persistrules::Kind;
        match e.kind {
            Kind::Suid | Kind::PamModule => Some(e.command.clone()),
            Kind::AuthorizedKey | Kind::Sudoers | Kind::Account | Kind::Pam => None,
            Kind::RcLocal | Kind::InitScript | Kind::Motd | Kind::ShellProfile => {
                Some(e.location.clone())
            }
            _ => persistrules::command_target(&e.command).or_else(|| Some(e.location.clone())),
        }
    }

    #[cfg(feature = "yara")]
    fn yara_phase(
        ui: &Ui,
        args: &Args,
        report: &mut Report,
        findings: &mut Vec<Finding>,
        mut targets: Targets,
    ) {
        use crate::linux::yara;
        targets.files.sort();
        targets.files.dedup_by(|a, b| a.0 == b.0);
        targets
            .files
            .retain(|(p, _)| std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false));
        if targets.mem.is_empty() && targets.files.is_empty() {
            ui.step("YARA: no suspicious regions or files to scan");
            return;
        }
        let counts = crate::rules::counts()
            .iter()
            .map(|(s, n)| format!("{s} {n}"))
            .collect::<Vec<_>>()
            .join(", ");
        ui.step(&format!("compiling YARA rules ({counts})"));
        let eng = match yara::engine(&args.extra_rules) {
            Ok(e) => e,
            Err(e) => {
                report.limitations.push(format!("YARA unavailable: {e}"));
                return;
            }
        };
        for s in &eng.skipped {
            report
                .limitations
                .push(format!("YARA rule file skipped: {s}"));
        }
        ui.step(&format!(
            "YARA: {} rule files, scanning {} memory regions and {} files",
            eng.loaded,
            targets.mem.len(),
            targets.files.len()
        ));
        let mut list: Vec<yara::Target> = targets
            .mem
            .into_iter()
            .map(|(pid, name, addr, len, label)| yara::Target::Mem {
                pid,
                name,
                addr,
                len,
                label,
            })
            .collect();
        list.extend(
            targets
                .files
                .into_iter()
                .map(|(path, label)| yara::Target::File { path, label }),
        );
        let max = if args.deep { 256 << 20 } else { 64 << 20 };
        findings.extend(yara::scan(eng, list, max));
    }

    /// SHA-256 of executables behind High/Critical process findings, for IOC sharing and sandboxing.
    fn enrich_hashes(findings: &mut [Finding], deep: bool) {
        let mut cache: HashMap<String, Option<String>> = HashMap::new();
        for f in findings.iter_mut() {
            if !(f.severity >= Severity::High || deep)
                || !matches!(
                    f.category,
                    Category::Process | Category::Network | Category::Yara
                )
            {
                continue;
            }
            let src = match (f.pid, f.category) {
                (Some(pid), Category::Process | Category::Network) => format!("/proc/{pid}/exe"),
                (None, _) => match &f.path {
                    Some(p) if p.starts_with('/') => p.clone(),
                    _ => continue,
                },
                _ => continue,
            };
            let h = cache.entry(src.clone()).or_insert_with(|| {
                let mut file = std::fs::File::open(&src).ok()?;
                let mut s = Sha256::new();
                std::io::copy(&mut file, &mut s).ok()?;
                Some(format!("{:x}", s.finalize()))
            });
            if let Some(h) = h {
                f.details.push(format!("sha256: {h}"));
            }
        }
    }

    /// Identical findings (same title, pid, path, address) collapse into one.
    fn dedup(v: &mut Vec<Finding>) {
        let mut seen = std::collections::HashSet::new();
        v.retain(|f| {
            seen.insert((
                f.title.clone(),
                f.pid,
                f.path.clone(),
                f.address.clone(),
                f.details.first().cloned(),
            ))
        });
    }
}
