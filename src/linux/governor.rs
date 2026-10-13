//! Resource governor: a sampler thread watches system CPU load and free memory, and workers call
//! `checkpoint()` before each heavy item (a process, a file hash, a web script, a YARA target).
//! Also lowers the scheduling and I/O priority for `--lowprio`.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::read_text;
use crate::core::resources::{
    cpu_percent, gate, parse_cpu_line, parse_meminfo, parse_proc_ticks, CpuSample, Gate, Limits,
};

pub struct Governor {
    limits: Limits,
    deadline: Option<Instant>,
    /// Latest system CPU percentage x100 and MemAvailable in MiB (u64::MAX = unknown).
    cpu_x100: AtomicU64,
    mem_avail: AtomicU64,
    stop: AtomicBool,
    paused_ms: AtomicU64,
    pub skipped_low_memory: AtomicUsize,
    pub skipped_deadline: AtomicUsize,
}

static GOV: OnceLock<Governor> = OnceLock::new();

const SAMPLE: Duration = Duration::from_millis(500);
/// A checkpoint never waits longer than this for CPU load to fall, so a host that is busy for
/// hours still gets scanned (slowly) instead of stalling forever.
const MAX_PAUSE: Duration = Duration::from_secs(10);

/// Install the governor and start its sampler. Safe to call once; later calls are ignored.
pub fn install(limits: Limits, max_runtime: Option<Duration>) {
    let g = Governor {
        limits,
        deadline: max_runtime.map(|d| Instant::now() + d),
        cpu_x100: AtomicU64::new(0),
        mem_avail: AtomicU64::new(u64::MAX),
        stop: AtomicBool::new(false),
        paused_ms: AtomicU64::new(0),
        skipped_low_memory: AtomicUsize::new(0),
        skipped_deadline: AtomicUsize::new(0),
    };
    if GOV.set(g).is_err() {
        return;
    }
    sample_once(None);
    let needs_sampler = limits.cpulimit < 100 || limits.minmem_mib > 0;
    if needs_sampler {
        std::thread::Builder::new()
            .name("exhume-governor".into())
            .spawn(|| {
                let mut prev = cpu_sample();
                loop {
                    std::thread::sleep(SAMPLE);
                    let Some(g) = GOV.get() else { return };
                    if g.stop.load(Ordering::Relaxed) {
                        return;
                    }
                    prev = sample_once(prev);
                }
            })
            .ok();
    }
}

fn sample_once(prev: Option<CpuSample>) -> Option<CpuSample> {
    let g = GOV.get()?;
    let cur = cpu_sample();
    if let (Some(p), Some(c)) = (prev, cur) {
        g.cpu_x100
            .store((cpu_percent(p, c) * 100.0) as u64, Ordering::Relaxed);
    }
    if let Some((_, avail)) = read_text("/proc/meminfo", 64 << 10).and_then(|t| parse_meminfo(&t)) {
        g.mem_avail.store(avail, Ordering::Relaxed);
    }
    cur
}

/// System CPU counters plus Exhume's own ticks, so the limit ignores Exhume's load.
fn cpu_sample() -> Option<CpuSample> {
    let mut s = read_text("/proc/stat", 64 << 10).and_then(|t| parse_cpu_line(&t))?;
    s.own = read_text("/proc/self/stat", 4096)
        .and_then(|t| parse_proc_ticks(&t))
        .unwrap_or(0);
    Some(s)
}

pub fn shutdown() {
    if let Some(g) = GOV.get() {
        g.stop.store(true, Ordering::Relaxed);
    }
}

fn current_gate(g: &Governor) -> Gate {
    let mem = g.mem_avail.load(Ordering::Relaxed);
    gate(
        g.limits,
        g.cpu_x100.load(Ordering::Relaxed) as f64 / 100.0,
        (mem != u64::MAX).then_some(mem),
        g.deadline.is_some_and(|d| Instant::now() >= d),
    )
}

/// Called by workers before a heavy item. Returns false when the item must be skipped (low
/// memory or runtime budget spent); waits while the system CPU is above `--cpulimit`.
pub fn checkpoint() -> bool {
    let Some(g) = GOV.get() else { return true };
    let start = Instant::now();
    loop {
        match current_gate(g) {
            Gate::Run => break,
            Gate::SkipDeadline => {
                g.skipped_deadline.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            Gate::SkipLowMemory => {
                g.skipped_low_memory.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            Gate::Pause if start.elapsed() >= MAX_PAUSE => break,
            Gate::Pause => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    let waited = start.elapsed().as_millis() as u64;
    if waited > 0 {
        g.paused_ms.fetch_add(waited, Ordering::Relaxed);
    }
    true
}

/// True once `--max-runtime` has passed (cheap check for loops that want to stop early).
pub fn expired() -> bool {
    GOV.get()
        .and_then(|g| g.deadline)
        .is_some_and(|d| Instant::now() >= d)
}

/// (paused seconds summed over workers, skipped for memory, skipped for deadline)
pub fn stats() -> (f64, usize, usize) {
    GOV.get()
        .map(|g| {
            (
                g.paused_ms.load(Ordering::Relaxed) as f64 / 1000.0,
                g.skipped_low_memory.load(Ordering::Relaxed),
                g.skipped_deadline.load(Ordering::Relaxed),
            )
        })
        .unwrap_or_default()
}

/// Lower CPU (nice 10) and I/O priority (idle class) of the calling thread. Linux applies both
/// per thread and new threads inherit them, so this must run before the worker pool starts.
pub fn lower_priority() -> bool {
    const IOPRIO_WHO_PROCESS: libc::c_int = 1;
    const IOPRIO_CLASS_IDLE: libc::c_int = 3;
    const IOPRIO_CLASS_SHIFT: libc::c_int = 13;
    let nice_ok = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 10) } == 0;
    let io_ok = unsafe {
        libc::syscall(
            libc::SYS_ioprio_set,
            IOPRIO_WHO_PROCESS,
            0,
            IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT,
        )
    } == 0;
    nice_ok || io_ok
}

/// Online CPU count.
pub fn cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

pub fn mem_total_mib() -> Option<u64> {
    read_text("/proc/meminfo", 64 << 10)
        .and_then(|t| parse_meminfo(&t))
        .map(|(t, _)| t)
}
