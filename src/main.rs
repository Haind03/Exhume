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
    use crate::core::resources;
    use crate::core::{
        injectrules, memrules, netrules, persistrules, procrules, timefmt, webshell, ProcInfo,
    };
    use crate::linux::{self, governor, mem, net, persist, pkg, procs, rootkit, suid, web};

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

        /// Worker threads; 0 = all cores, negative = all cores minus N [default: half the cores]
        #[arg(
            long,
            value_name = "N",
            allow_negative_numbers = true,
            help_heading = "Performance and resource control"
        )]
        threads: Option<i64>,
        /// Pause work while total system CPU usage is above this percentage (100 = never pause)
        #[arg(long, value_name = "PCT", default_value_t = 95, value_parser = clap::value_parser!(u8).range(15..=100), help_heading = "Performance and resource control")]
        cpulimit: u8,
        /// Skip heavy items (memory reads, hashing, YARA) while available memory is below MiB (0 = off)
        #[arg(
            long,
            value_name = "MiB",
            default_value_t = 100,
            help_heading = "Performance and resource control"
        )]
        minmem: u64,
        /// Lower CPU (nice 10) and I/O (idle class) priority
        #[arg(long, help_heading = "Performance and resource control")]
        lowprio: bool,
        /// Gentle mode for fragile hosts: 1 thread, low priority, cpulimit 70, no --deep, no PID sweep
        #[arg(long, help_heading = "Performance and resource control")]
        soft: bool,
        /// Never switch soft mode on automatically (it does on 1-core or <1 GiB RAM hosts)
        #[arg(long, help_heading = "Performance and resource control")]
        nosoft: bool,
        /// Largest file read for hashing/YARA in MiB [default: 64, 256 with --deep]
        #[arg(
            long,
            value_name = "MiB",
            help_heading = "Performance and resource control"
        )]
        max_file_size: Option<u64>,
        /// Largest memory region read for YARA in MiB [default: 64, 256 with --deep]
        #[arg(
            long,
            value_name = "MiB",
            help_heading = "Performance and resource control"
        )]
        max_region_size: Option<u64>,
        /// Abort any single YARA scan after this many seconds
        #[arg(
            long,
            value_name = "SECS",
            default_value_t = 20,
            help_heading = "Performance and resource control"
        )]
        yara_timeout: u64,
        /// Filesystem modules (persistence, SUID, webshells) only report files changed in the last N days
        #[arg(
            long,
            value_name = "DAYS",
            help_heading = "Performance and resource control"
        )]
        lookback: Option<u64>,
        /// Stop optional work (hashing, YARA, sweeps) after this many minutes and report what was done (0 = no limit)
        #[arg(
            long,
            value_name = "MINUTES",
            help_heading = "Performance and resource control"
        )]
        max_runtime: Option<u64>,
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
        // ---- resource control: decided before any worker thread exists, because nice and
        // ioprio are per thread on Linux and inherited by threads created afterwards.
        let cores = governor::cores();
        let auto_soft = !args.nosoft && resources::auto_soft(cores, governor::mem_total_mib());
        let soft = args.soft || auto_soft;
        let deep = args.deep && !soft;
        if args.deep && soft {
            report
                .limitations
                .push("--deep ignored in soft mode".into());
        }
        report.deep = deep;
        let threads = if soft && args.threads.is_none() {
            1
        } else {
            resources::resolve_threads(args.threads, cores)
        };
        let cpulimit = if soft {
            args.cpulimit.min(70)
        } else {
            args.cpulimit
        };
        let lowprio = (args.lowprio || soft) && governor::lower_priority();
        governor::install(
            resources::Limits {
                cpulimit,
                minmem_mib: args.minmem,
            },
            args.max_runtime
                .filter(|m| *m > 0)
                .map(|m| std::time::Duration::from_secs(m * 60)),
        );
        let opts = Opts {
            deep,
            pid_sweep: !args.no_pid_bruteforce && !soft,
            lookback: args.lookback,
            max_file: args.max_file_size.map(|m| m << 20).unwrap_or(if deep {
                256 << 20
            } else {
                64 << 20
            }) as usize,
            max_region: args.max_region_size.map(|m| m << 20).unwrap_or(if deep {
                256 << 20
            } else {
                64 << 20
            }) as usize,
        };
        report.stats = resources::ScanStats {
            threads,
            cpulimit,
            minmem_mib: args.minmem,
            soft,
            lowprio,
            lookback_days: args.lookback.filter(|d| *d > 0),
            ..Default::default()
        };
        ui.step(&format!(
            "{threads} worker thread(s) on {cores} core(s){}{}, cpulimit {cpulimit}%",
            if soft {
                if auto_soft {
                    ", soft mode (auto)"
                } else {
                    ", soft mode"
                }
            } else {
                ""
            },
            if lowprio { ", low priority" } else { "" }
        ));
        let pool = match rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("exhume-{i}"))
            .build()
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cannot start worker threads: {e}");
                return 1;
            }
        };
        let phases = Phases::default();
        let mut findings = pool.install(|| hunt(&args, &ui, &opts, &mut report, &phases));
        governor::shutdown();
        let (paused, low_mem, deadline) = governor::stats();
        report.stats.paused_secs = paused;
        report.stats.skipped_low_memory = low_mem;
        report.stats.skipped_deadline = deadline;
        report.stats.phases = phases.0.into_inner().unwrap_or_default();
        if low_mem > 0 {
            report.limitations.push(format!(
                "{low_mem} heavy items skipped because available memory was below --minmem {} MiB",
                args.minmem
            ));
        }
        if deadline > 0 {
            report.limitations.push(format!(
                "{deadline} items skipped after --max-runtime ran out"
            ));
        }
        if let Some(d) = args.lookback.filter(|d| *d > 0) {
            report.limitations.push(format!("--lookback {d}: files changed earlier were not reported by the persistence, SUID and webshell modules"));
        }

        // ---- IR enrichment and output
        enrich_hashes(&mut findings, opts.deep);
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

    /// Scan-wide options after soft mode and defaults are applied.
    struct Opts {
        deep: bool,
        pid_sweep: bool,
        lookback: Option<u64>,
        #[cfg_attr(not(feature = "yara"), allow(dead_code))]
        max_file: usize,
        #[cfg_attr(not(feature = "yara"), allow(dead_code))]
        max_region: usize,
    }

    /// Wall-clock time of each phase, in completion order (phases run concurrently).
    #[derive(Default)]
    struct Phases(std::sync::Mutex<Vec<(String, f64)>>);

    impl Phases {
        fn time<T>(&self, name: &str, f: impl FnOnce() -> T) -> T {
            let t = Instant::now();
            let r = f();
            if let Ok(mut v) = self.0.lock() {
                v.push((name.to_string(), t.elapsed().as_secs_f64()));
            }
            r
        }
    }

    /// The whole hunt, run inside the worker pool. Processes are scanned first (their results
    /// feed socket mapping and YARA), then the host-wide modules run concurrently with each other,
    /// and YARA scans everything flagged on the way, largest items first.
    fn hunt(args: &Args, ui: &Ui, o: &Opts, report: &mut Report, ph: &Phases) -> Vec<Finding> {
        let root = report.root;
        let mut findings: Vec<Finding> = Vec::new();
        let mut targets = Targets::default();
        let now = linux::now();

        // ---- processes (and the package database, loaded meanwhile)
        ui.step("enumerating processes, loading package database");
        let self_pid = std::process::id();
        let ((procs, sockets), db) = rayon::join(
            || {
                ph.time("process snapshot", || {
                    let procs: Vec<ProcInfo> = linux::list_pids()
                        .par_iter()
                        .filter(|&&p| p != self_pid)
                        .filter_map(|&p| procs::collect(p))
                        .collect();
                    let sockets = net::sockets(&procs);
                    (procs, sockets)
                })
            },
            || ph.time("package database", pkg::PkgDb::load),
        );
        report.processes_scanned = procs.len();
        let restricted = procs.iter().filter(|p| p.restricted && !p.kthread).count();
        if restricted > 0 {
            report.limitations.push(format!(
                "{restricted} processes only partially readable (permission denied)"
            ));
        }
        if db.manager == pkg::Manager::None {
            report.limitations.push(
                "no dpkg/rpm database: package ownership and integrity checks skipped".into(),
            );
        }
        report.sockets = sockets;
        let inet = net::inet_map(&report.sockets);
        let by_pid: HashMap<u32, &ProcInfo> = procs.iter().map(|p| (p.pid, p)).collect();

        ui.step(&format!(
            "scanning {} processes (process, injection, memory)",
            procs.len()
        ));
        let per_proc: Vec<(Vec<Finding>, Targets)> = ph.time("processes and memory", || {
            procs
                .par_iter()
                // One process per task: a single huge process must not hold back a batch.
                .with_max_len(1)
                .filter(|p| !p.kthread || procrules::looks_like_kthread(&p.comm))
                .map(|p| scan_process(p, &by_pid, &inet, o.deep))
                .collect()
        });
        for (f, t) in per_proc {
            findings.extend(f);
            targets.mem.extend(t.mem);
            targets.files.extend(t.files);
        }

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
        findings.extend(netrules::analyze(&report.sockets, root));

        // ---- host-wide modules, concurrently
        ui.step("rootkit cross-views, persistence, SUID sweep, webshells and package integrity in parallel");
        let ((rk, pers), (webs, integ)) = rayon::join(
            || {
                rayon::join(
                    || ph.time("rootkit cross-views", || rootkit_phase(ui, o, root)),
                    || {
                        ph.time("persistence and SUID", || {
                            persistence_phase(ui, o, &db, now)
                        })
                    },
                )
            },
            || {
                rayon::join(
                    || ph.time("webshells", || webshell_phase(ui, o, now)),
                    || ph.time("package integrity", || pkg::verify(&db, o.deep)),
                )
            },
        );
        findings.extend(rk.0);
        report.limitations.extend(rk.1);
        findings.extend(pers.0);
        targets.files.extend(pers.1);
        findings.extend(webs.0);
        targets.files.extend(webs.1);
        if db.manager != pkg::Manager::None {
            ui.step(&format!(
                "verified {} packaged files ({})",
                integ.1,
                db.name()
            ));
        }
        findings.extend(integ.0);

        // ---- YARA
        #[cfg(feature = "yara")]
        if !args.no_yara {
            ph.time("yara", || {
                yara_phase(ui, args, o, report, &mut findings, targets)
            });
        }
        #[cfg(not(feature = "yara"))]
        {
            let _ = (targets, args);
            report
                .limitations
                .push("built without the yara feature".into());
        }
        findings
    }

    fn rootkit_phase(ui: &Ui, o: &Opts, root: bool) -> (Vec<Finding>, Vec<String>) {
        let mut out = Vec::new();
        let mut limits = Vec::new();
        let (hidden, kernel) = rayon::join(
            || {
                if o.pid_sweep && !governor::expired() {
                    rootkit::hidden_processes()
                } else {
                    Vec::new()
                }
            },
            || {
                let mut v = rootkit::modules(root);
                v.extend(rootkit::taint());
                v
            },
        );
        out.extend(hidden);
        out.extend(kernel);
        match rootkit::bpf_programs() {
            Ok(p) => out.extend(crate::core::rootkit::bpf_findings(&p)),
            Err(e) if rootkit::bpf_available() => {
                limits.push(format!("eBPF programs not enumerated: {e}"))
            }
            Err(_) => {}
        }
        ui.step("rootkit cross-views done");
        (out, limits)
    }

    fn persistence_phase(
        ui: &Ui,
        o: &Opts,
        db: &pkg::PkgDb,
        now: u64,
    ) -> (Vec<Finding>, Vec<(String, String)>) {
        let (entries, (suids, files_seen)) = rayon::join(
            || persist::collect(db),
            || suid::sweep(o.deep, &|p| db.owns(p)),
        );
        ui.step(&format!("swept {files_seen} files for SUID/SGID bits"));
        let mut out = Vec::new();
        let mut files = Vec::new();
        for e in entries.iter().chain(suids.iter()) {
            if !resources::in_lookback(e.mtime, now, o.lookback) {
                continue;
            }
            if let Some(f) = persistrules::score(e, now) {
                if f.severity >= Severity::Low {
                    if let Some(t) = persist_target(e) {
                        files.push((t, format!("{} target", e.kind.label())));
                    }
                }
                out.push(f);
            }
        }
        (out, files)
    }

    fn webshell_phase(ui: &Ui, o: &Opts, now: u64) -> (Vec<Finding>, Vec<(String, String)>) {
        let roots = web::roots(&linux::homes());
        let mut scripts = web::scripts(&roots, if o.deep { usize::MAX } else { 50_000 });
        scripts.retain(|(_, mtime, _)| resources::in_lookback(Some(*mtime), now, o.lookback));
        ui.step(&format!(
            "hunting webshells: {} server-side scripts under {} web roots",
            scripts.len(),
            roots.len()
        ));
        let found: Vec<Finding> = scripts
            .par_iter()
            .filter_map(|(path, mtime, _)| {
                if !governor::checkpoint() {
                    return None;
                }
                let text = linux::read_text(path, 2 << 20)?;
                webshell::analyze(&webshell::WebFile {
                    path,
                    content: &text,
                    mtime: Some(*mtime),
                    now,
                })
            })
            .collect();
        let yara_web = if o.deep { usize::MAX } else { 20_000 };
        let files = scripts
            .into_iter()
            .filter(|(_, _, size)| *size <= 4 << 20)
            .take(yara_web)
            .map(|(p, _, _)| (p, "web script".to_string()))
            .collect();
        (found, files)
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

        // Memory work is the heavy part: it waits for --cpulimit and is skipped on low memory.
        if !governor::checkpoint() {
            return (out, t);
        }
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
        o: &Opts,
        report: &mut Report,
        findings: &mut Vec<Finding>,
        mut targets: Targets,
    ) {
        use crate::linux::yara;
        use std::os::unix::fs::MetadataExt;
        targets.files.sort();
        targets.files.dedup_by(|a, b| a.0 == b.0);
        // The same file reached through several paths (/proc/<pid>/exe of every bash, a unit's
        // target, a SUID copy...) is scanned once: identity is device + inode, not the path.
        let mut seen_ids = std::collections::HashSet::new();
        let before = targets.files.len();
        targets.files.retain(|(p, _)| match std::fs::metadata(p) {
            Ok(m) if m.is_file() => seen_ids.insert((m.dev(), m.ino())),
            _ => false,
        });
        report.stats.yara_duplicates_skipped = before - targets.files.len();
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
        let scan_opts = yara::ScanOpts {
            max_file: o.max_file,
            max_region: o.max_region,
            timeout: std::time::Duration::from_secs(args.yara_timeout.max(1)),
        };
        findings.extend(yara::scan(eng, list, &scan_opts));
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
                let mut file = linux::open_regular(&src).ok()?;
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
