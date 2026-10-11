//! Memory heuristics over /proc/<pid>/maps: anonymous executable code, RWX pages, ELF images in
//! anonymous memory (reflective loading), memfd-backed and deleted mappings, odd library paths.

use std::collections::HashMap;

use super::paths::{file_name, memfd_name, strip_deleted, suspicious_location};
use super::procrules::benign_memfd;
use super::report::{Category, Finding, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    pub shared: bool,
    pub offset: u64,
    pub inode: u64,
    /// Pathname column ("" for anonymous, "[heap]", "/memfd:x (deleted)", ...).
    pub path: String,
}

impl Mapping {
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn perms(&self) -> String {
        format!(
            "{}{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.exec { 'x' } else { '-' },
            if self.shared { 's' } else { 'p' }
        )
    }

    /// Not backed by a file on disk (includes [heap], [stack] and memfd).
    pub fn anonymous(&self) -> bool {
        self.path.is_empty()
            || self.path == "[heap]"
            || self.path.starts_with("[stack")
            || self.path.starts_with("[anon")
    }

    /// Kernel-provided special mappings that are always executable.
    pub fn special(&self) -> bool {
        matches!(
            self.path.as_str(),
            "[vdso]" | "[vsyscall]" | "[uprobes]" | "[vectors]" | "[sigpage]"
        )
    }
}

/// Parse one line of /proc/<pid>/maps.
pub fn parse_maps_line(line: &str) -> Option<Mapping> {
    let mut it = line.splitn(6, ' ');
    let range = it.next()?;
    let perms = it.next()?.as_bytes();
    let offset = u64::from_str_radix(it.next()?, 16).ok()?;
    let _dev = it.next()?;
    let inode = it.next()?.parse().ok()?;
    let path = it.next().unwrap_or("").trim_start().to_string();
    let (s, e) = range.split_once('-')?;
    if perms.len() < 4 {
        return None;
    }
    Some(Mapping {
        start: u64::from_str_radix(s, 16).ok()?,
        end: u64::from_str_radix(e, 16).ok()?,
        read: perms[0] == b'r',
        write: perms[1] == b'w',
        exec: perms[2] == b'x',
        shared: perms[3] == b's',
        offset,
        inode,
        path,
    })
}

pub fn parse_maps(text: &str) -> Vec<Mapping> {
    text.lines().filter_map(parse_maps_line).collect()
}

/// Processes that JIT-compile code, so anonymous executable memory is expected.
const JIT_NAMES: &[&str] = &[
    "java",
    "node",
    "nodejs",
    "chrome",
    "chromium",
    "firefox",
    "firefox-esr",
    "thunderbird",
    "code",
    "electron",
    "dotnet",
    "mono",
    "qemu",
    "luajit",
    "pypy",
    "pypy3",
    "deno",
    "bun",
    "julia",
    "beam.smp",
    "erl",
    "gnome-shell",
    "slack",
    "teams",
    "Web Content",
    "WebExtensions",
    "Isolated Web Co",
    "RDD Process",
    "Socket Process",
    "Privileged Cont",
    "GeckoMain",
    "msedge",
    "brave",
    "opera",
    "vivaldi",
    "spotify",
    "discord",
    "signal-desktop",
    "obsidian",
    "cursor",
    "postgres",
    "php-fpm",
    "Xorg",
    "Xwayland",
    "kwin_wayland",
    "kwin_x11",
    "plasmashell",
    "steam",
    "wine",
    "wine64",
    "wineserver",
    "valgrind",
];

const JIT_LIBS: &[&str] = &[
    "libjvm.so",
    "libnode.so",
    "libv8.so",
    "libmozjs",
    "libxul.so",
    "libcoreclr.so",
    "libclrjit.so",
    "libmonosgen",
    "libluajit",
    "libpcre2-8.so",
    "libpcre.so",
    "libjavascriptcoregtk",
    "libwebkit2gtk",
    "libQt5Qml.so",
    "libQt6Qml.so",
    "libgjs.so",
    "libLLVM",
    "libmozgtk",
    "libpython3",
    "libruby",
    "libwasmtime",
    "libgallium",
    "libGLX",
    "libEGL",
    "libnvidia",
    "libvulkan",
    "libmesa",
    "libOSMesa",
    "liborc-0.4.so",
    "libgstreamer",
    "libcuda",
];

/// The process hosts a JIT, so anonymous executable pages alone mean little.
pub fn is_jit(name: &str, maps: &[Mapping]) -> bool {
    let n = name.to_ascii_lowercase();
    if JIT_NAMES.iter().any(|j| {
        n == j.to_ascii_lowercase() || n.starts_with(&format!("{}-", j.to_ascii_lowercase()))
    }) || n.starts_with("python")
    {
        return true;
    }
    maps.iter().any(|m| {
        let f = file_name(&m.path);
        JIT_LIBS.iter().any(|l| f.starts_with(l))
    })
}

/// ELF magic plus a sane class/data/type: a mapped program image rather than four random bytes.
pub fn elf_header(b: &[u8]) -> Option<&'static str> {
    if b.len() < 20 || &b[..4] != b"\x7fELF" {
        return None;
    }
    if !(b[4] == 1 || b[4] == 2) || !(b[5] == 1 || b[5] == 2) {
        return None;
    }
    let ty = if b[5] == 1 {
        u16::from_le_bytes([b[16], b[17]])
    } else {
        u16::from_be_bytes([b[16], b[17]])
    };
    match ty {
        2 => Some("ELF executable (ET_EXEC)"),
        3 => Some("ELF shared object / PIE (ET_DYN)"),
        1 => Some("ELF relocatable object (ET_REL)"),
        _ => None,
    }
}

/// Everything the memory rules need for one process.
pub struct MemView<'a> {
    pub pid: u32,
    pub name: &'a str,
    pub maps: &'a [Mapping],
    /// First bytes of selected anonymous regions, keyed by start address.
    pub peeks: &'a HashMap<u64, Vec<u8>>,
    pub deep: bool,
}

/// Regions worth peeking at (and later YARA-scanning): anonymous executable or memfd mappings.
pub fn peek_candidates(maps: &[Mapping], deep: bool) -> Vec<&Mapping> {
    maps.iter()
        .filter(|m| m.read && !m.special())
        .filter(|m| (m.anonymous() && (m.exec || deep)) || memfd_name(&m.path).is_some())
        .collect()
}

pub fn analyze(v: &MemView) -> Vec<Finding> {
    let mut out = Vec::new();
    let jit = is_jit(v.name, v.maps);
    let f = |sev, title: &str, m: &Mapping| {
        Finding::new(sev, Category::Memory, title)
            .proc(v.pid, v.name)
            .addr(m.start)
            .detail(format!(
                "{} {} KiB {}",
                m.perms(),
                m.size() / 1024,
                if m.path.is_empty() { "[anon]" } else { &m.path }
            ))
    };

    let mut anon_x = 0usize;
    let mut first_anon_x: Option<&Mapping> = None;
    for m in v.maps {
        if m.special() {
            continue;
        }
        let peek = v.peeks.get(&m.start).map(Vec::as_slice).unwrap_or(&[]);
        let elf = elf_header(peek);

        if m.anonymous() {
            if let Some(kind) = elf {
                let sev = if m.exec {
                    Severity::Critical
                } else if v.deep {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                if m.exec || !jit {
                    out.push(
                        f(sev, "ELF image in anonymous memory (reflective loading)", m)
                            .detail(kind)
                            .detail("an ELF header in memory that no file backs: in-memory loader or unpacked implant")
                            .mitre(&["T1620", "T1055.009"]),
                    );
                }
            }
            if m.exec {
                if m.write && !jit {
                    // Multi-MiB RWX reservations are how embedded JS/WASM engines lay out code caches;
                    // shellcode stagers allocate far smaller regions.
                    if m.size() >= 16 << 20 {
                        out.push(
                            f(
                                Severity::Medium,
                                "Large writable and executable (RWX) anonymous region",
                                m,
                            )
                            .detail(
                                "size typical of an embedded JIT code cache; verify the process",
                            )
                            .mitre(&["T1055"]),
                        );
                    } else {
                        out.push(
                            f(
                                Severity::High,
                                "Writable and executable (RWX) anonymous memory",
                                m,
                            )
                            .mitre(&["T1055", "T1620"]),
                        );
                    }
                } else if !jit && elf.is_none() {
                    anon_x += 1;
                    first_anon_x.get_or_insert(m);
                }
            }
            continue;
        }

        if let Some(mname) = memfd_name(&m.path) {
            if m.exec && !benign_memfd(mname) {
                out.push(
                    f(
                        Severity::Critical,
                        "Executable code mapped from a memfd (fileless)",
                        m,
                    )
                    .detail(format!("memfd name: '{mname}'"))
                    .mitre(&["T1620", "T1027.011"]),
                );
            } else if elf.is_some() && !benign_memfd(mname) {
                out.push(f(Severity::High, "ELF image held in a memfd", m).mitre(&["T1620"]));
            }
            continue;
        }

        if m.exec && m.path.starts_with('/') {
            let (path, deleted) = strip_deleted(&m.path);
            // libffi closure trampolines: a temp file created, unlinked and mapped executable.
            let ffi_tramp =
                deleted && file_name(path).starts_with("ffi") && file_name(path).len() == 9;
            if ffi_tramp {
                continue;
            }
            if let Some(why) = suspicious_location(path) {
                out.push(
                    f(
                        Severity::High,
                        "Executable mapping from a suspicious location",
                        m,
                    )
                    .path(path)
                    .detail(why)
                    .mitre(&["T1574.006", "T1055.009"]),
                );
            } else if deleted
                && m.offset == 0
                && !path.starts_with("/usr/")
                && !path.starts_with("/lib")
            {
                out.push(
                    f(Severity::Medium, "Executable mapping of a deleted file", m)
                        .path(path)
                        .mitre(&["T1070.004"]),
                );
            }
        }
    }

    if anon_x > 0 {
        let m = first_anon_x.unwrap();
        out.push(
            f(
                Severity::Medium,
                "Anonymous executable memory in a non-JIT process",
                m,
            )
            .detail(format!(
                "{anon_x} anonymous r-x region(s); possible shellcode or injected loader"
            ))
            .mitre(&["T1055", "T1620"]),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS: &str = "\
55d4c0a00000-55d4c0a28000 r--p 00000000 fd:01 1311 /usr/bin/bash
55d4c0a28000-55d4c0af1000 r-xp 00028000 fd:01 1311 /usr/bin/bash
7f0000000000-7f0000021000 rwxp 00000000 00:00 0
7f0000100000-7f0000101000 r-xp 00000000 00:00 0
7f0000200000-7f0000210000 r-xp 00000000 00:01 4242 /memfd:x (deleted)
7f0000300000-7f0000301000 r-xp 00000000 08:01 99 /dev/shm/libhide.so
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0                          [stack]
7ffd00100000-7ffd00102000 r-xp 00000000 00:00 0                          [vdso]
";

    #[test]
    fn parse() {
        let m = parse_maps(MAPS);
        assert_eq!(m.len(), 8);
        assert_eq!(m[1].start, 0x55d4c0a28000);
        assert!(m[1].exec && !m[1].write);
        assert_eq!(m[1].offset, 0x28000);
        assert_eq!(m[1].path, "/usr/bin/bash");
        assert!(m[2].anonymous() && m[2].write && m[2].exec);
        assert_eq!(m[4].path, "/memfd:x (deleted)");
        assert_eq!(m[6].path, "[stack]");
        assert!(m[7].special());
        assert_eq!(m[2].perms(), "rwxp");
    }

    #[test]
    fn findings() {
        let maps = parse_maps(MAPS);
        let mut peeks = HashMap::new();
        let mut elf = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x03\0\x3e\0".to_vec();
        elf.resize(64, 0);
        peeks.insert(0x7f0000100000u64, elf);
        let v = MemView {
            pid: 7,
            name: "bash",
            maps: &maps,
            peeks: &peeks,
            deep: false,
        };
        let f = analyze(&v);
        let t: Vec<_> = f.iter().map(|x| (x.severity, x.title.as_str())).collect();
        assert!(
            t.contains(&(
                Severity::High,
                "Writable and executable (RWX) anonymous memory"
            )),
            "{t:?}"
        );
        assert!(t.contains(&(
            Severity::Critical,
            "ELF image in anonymous memory (reflective loading)"
        )));
        assert!(t.contains(&(
            Severity::Critical,
            "Executable code mapped from a memfd (fileless)"
        )));
        assert!(t.contains(&(
            Severity::High,
            "Executable mapping from a suspicious location"
        )));
        assert!(
            !t.iter().any(|x| x.1.contains("non-JIT")),
            "the only r-x anon region held an ELF"
        );
    }

    #[test]
    fn jit_quiet() {
        let maps = parse_maps(MAPS);
        let peeks = HashMap::new();
        let v = MemView {
            pid: 7,
            name: "java",
            maps: &maps,
            peeks: &peeks,
            deep: false,
        };
        let f = analyze(&v);
        assert!(!f
            .iter()
            .any(|x| x.title.contains("RWX") || x.title.contains("non-JIT")));
        // memfd and /dev/shm library are still reported in a JIT.
        assert!(f.iter().any(|x| x.title.contains("memfd")));
    }

    #[test]
    fn jit_sized_rwx_and_ffi_trampolines() {
        let maps = parse_maps(
            "7f0000000000-7f0004000000 rwxp 00000000 00:00 0 \n7f1000000000-7f1000001000 r-xs 00000000 00:1e 77 /tmp/ffiAbC123 (deleted)\n",
        );
        let peeks = HashMap::new();
        let f = analyze(&MemView {
            pid: 1,
            name: "agent",
            maps: &maps,
            peeks: &peeks,
            deep: false,
        });
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].title.starts_with("Large"));
    }

    #[test]
    fn elf_magic() {
        let mut b = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0".to_vec();
        b.resize(64, 0);
        assert_eq!(elf_header(&b), Some("ELF executable (ET_EXEC)"));
        b[4] = 9;
        assert_eq!(elf_header(&b), None);
        assert_eq!(elf_header(b"\x7fELF"), None);
    }

    #[test]
    fn candidates() {
        let maps = parse_maps(MAPS);
        let c = peek_candidates(&maps, false);
        assert_eq!(c.len(), 3, "rwx anon, r-x anon, memfd");
        assert!(peek_candidates(&maps, true).len() > c.len());
    }
}
