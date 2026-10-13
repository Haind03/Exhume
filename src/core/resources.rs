//! Scan scheduling and resource-control decisions, kept pure so they are unit-tested: thread
//! count resolution, CPU load from /proc/stat samples, free memory from /proc/meminfo, automatic
//! soft mode, lookback windows and largest-first work ordering.

use serde::Serialize;

/// `--threads` semantics: a positive number is used as is; zero or a negative number is
/// subtracted from the core count (0 = all cores, -2 = all but two). `None` picks the default for
/// live systems: half the cores, so the host keeps headroom for its own workload.
pub fn resolve_threads(requested: Option<i64>, cores: usize) -> usize {
    let cores = cores.max(1) as i64;
    let n = match requested {
        Some(r) if r > 0 => r,
        Some(r) => cores + r,
        None => (cores + 1) / 2,
    };
    n.clamp(1, 1024) as usize
}

/// Aggregate CPU time from the `cpu ` line of /proc/stat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuSample {
    pub busy: u64,
    pub total: u64,
    /// CPU ticks used by Exhume itself (utime + stime of all its threads).
    pub own: u64,
}

/// Parse the first (`cpu `) line of /proc/stat: user nice system idle iowait irq softirq steal ...
pub fn parse_cpu_line(stat: &str) -> Option<CpuSample> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let v: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    if v.len() < 4 {
        return None;
    }
    // guest and guest_nice (fields 9, 10) are already included in user and nice.
    let total: u64 = v.iter().take(8).sum();
    let idle = v[3] + v.get(4).copied().unwrap_or(0);
    Some(CpuSample {
        busy: total.saturating_sub(idle),
        total,
        own: 0,
    })
}

/// utime + stime (clock ticks, same unit as /proc/stat) from a /proc/<pid>/stat line.
pub fn parse_proc_ticks(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
}

/// CPU usage of everything except Exhume, in percent of all cores, between two samples.
///
/// The limit protects the host's own workload: counting Exhume's threads would make a scan that
/// uses every core throttle itself.
pub fn cpu_percent(prev: CpuSample, cur: CpuSample) -> f64 {
    let dt = cur.total.saturating_sub(prev.total);
    if dt == 0 {
        return 0.0;
    }
    let busy = cur.busy.saturating_sub(prev.busy);
    let own = cur.own.saturating_sub(prev.own);
    100.0 * busy.saturating_sub(own) as f64 / dt as f64
}

/// (MemTotal, MemAvailable) in MiB from /proc/meminfo.
pub fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
    let get = |key: &str| {
        text.lines().find_map(|l| {
            l.strip_prefix(key)?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
    };
    let total = get("MemTotal:")?;
    let avail =
        get("MemAvailable:").or_else(|| Some(get("MemFree:")? + get("Cached:").unwrap_or(0)))?;
    Some((total / 1024, avail / 1024))
}

/// Soft mode switches on by itself on hosts that cannot spare resources for a scan.
pub fn auto_soft(cores: usize, mem_total_mib: Option<u64>) -> bool {
    cores <= 1 || mem_total_mib.is_some_and(|m| m < 1024)
}

/// What a worker should do at a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Run,
    /// System CPU above the limit: wait and re-check.
    Pause,
    /// Free memory below the floor: skip the heavy item.
    SkipLowMemory,
    /// The runtime budget is spent: skip all remaining optional work.
    SkipDeadline,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Pause above this system-wide CPU percentage (100 = never pause).
    pub cpulimit: u8,
    /// Skip heavy items while MemAvailable is below this many MiB (0 = never).
    pub minmem_mib: u64,
}

pub fn gate(
    limits: Limits,
    cpu_pct: f64,
    mem_avail_mib: Option<u64>,
    deadline_passed: bool,
) -> Gate {
    if deadline_passed {
        Gate::SkipDeadline
    } else if limits.minmem_mib > 0 && mem_avail_mib.is_some_and(|m| m < limits.minmem_mib) {
        Gate::SkipLowMemory
    } else if limits.cpulimit < 100 && cpu_pct > limits.cpulimit as f64 {
        Gate::Pause
    } else {
        Gate::Run
    }
}

/// `--lookback`: is a file changed at `mtime` inside the window? No window = always.
pub fn in_lookback(mtime: Option<u64>, now: u64, days: Option<u64>) -> bool {
    match (days, mtime) {
        (None, _) | (Some(0), _) => true,
        (Some(_), None) => true, // unknown time: keep rather than silently drop
        (Some(d), Some(m)) => now.saturating_sub(m) <= d * 86_400,
    }
}

/// Longest-processing-time-first ordering: big work items start early so the pool does not end
/// with one thread chewing a large region while the others sit idle.
#[cfg_attr(not(feature = "yara"), allow(dead_code))]
pub fn largest_first<T>(items: &mut [T], size: impl Fn(&T) -> u64) {
    items.sort_by_key(|t| std::cmp::Reverse(size(t)));
}

/// Scan statistics included in the report.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanStats {
    pub threads: usize,
    pub cpulimit: u8,
    pub minmem_mib: u64,
    pub soft: bool,
    pub lowprio: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lookback_days: Option<u64>,
    /// Seconds workers spent paused because of --cpulimit.
    pub paused_secs: f64,
    pub skipped_low_memory: usize,
    pub skipped_deadline: usize,
    /// YARA targets dropped because they were the same file (same device and inode).
    pub yara_duplicates_skipped: usize,
    /// (phase, seconds), in completion order.
    pub phases: Vec<(String, f64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threads() {
        assert_eq!(resolve_threads(None, 8), 4);
        assert_eq!(resolve_threads(None, 1), 1);
        assert_eq!(resolve_threads(None, 3), 2);
        assert_eq!(resolve_threads(Some(0), 8), 8);
        assert_eq!(resolve_threads(Some(-2), 8), 6);
        assert_eq!(resolve_threads(Some(-20), 8), 1);
        assert_eq!(resolve_threads(Some(3), 8), 3);
        assert_eq!(resolve_threads(Some(5000), 8), 1024);
    }

    #[test]
    fn cpu() {
        let a = parse_cpu_line("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3 4\n").unwrap();
        assert_eq!(
            a,
            CpuSample {
                busy: 200,
                total: 1000,
                own: 0
            }
        );
        let b = parse_cpu_line("cpu  400 0 200 1300 100 0 0 0 0 0\n").unwrap();
        assert!((cpu_percent(a, b) - 40.0).abs() < 1e-9);
        assert_eq!(cpu_percent(b, b), 0.0);
        // 400 of the 1000 elapsed ticks were busy, 300 of them Exhume's own: others used 10 %.
        let a2 = CpuSample { own: 100, ..a };
        let b2 = CpuSample { own: 400, ..b };
        assert!((cpu_percent(a2, b2) - 10.0).abs() < 1e-9);
        let st = "4242 (exhume x) S 1 4242 4242 0 -1 4194560 10 0 0 0 150 50 0 0 20 0 8 0";
        assert_eq!(parse_proc_ticks(st), Some(200));
        assert!(parse_cpu_line("intr 1 2 3").is_none());
    }

    #[test]
    fn meminfo() {
        let t = "MemTotal:       16384000 kB\nMemFree:         1000000 kB\nMemAvailable:    8192000 kB\n";
        assert_eq!(parse_meminfo(t), Some((16000, 8000)));
        let old = "MemTotal: 2048000 kB\nMemFree: 102400 kB\nCached: 102400 kB\n";
        assert_eq!(parse_meminfo(old), Some((2000, 200)));
        assert!(auto_soft(1, Some(8000)));
        assert!(auto_soft(8, Some(900)));
        assert!(!auto_soft(8, Some(8000)));
        assert!(!auto_soft(4, None));
    }

    #[test]
    fn gating() {
        let l = Limits {
            cpulimit: 80,
            minmem_mib: 100,
        };
        assert_eq!(gate(l, 50.0, Some(4000), false), Gate::Run);
        assert_eq!(gate(l, 95.0, Some(4000), false), Gate::Pause);
        assert_eq!(gate(l, 95.0, Some(50), false), Gate::SkipLowMemory);
        assert_eq!(gate(l, 10.0, Some(4000), true), Gate::SkipDeadline);
        let off = Limits {
            cpulimit: 100,
            minmem_mib: 0,
        };
        assert_eq!(gate(off, 100.0, Some(1), false), Gate::Run);
    }

    #[test]
    fn lookback_and_order() {
        let now = 10 * 86_400;
        assert!(in_lookback(Some(now - 86_400), now, Some(2)));
        assert!(!in_lookback(Some(now - 3 * 86_400), now, Some(2)));
        assert!(in_lookback(Some(0), now, None));
        assert!(in_lookback(None, now, Some(1)));
        let mut v = vec![3u64, 10, 1, 7];
        largest_first(&mut v, |x| *x);
        assert_eq!(v, vec![10, 7, 3, 1]);
    }
}
