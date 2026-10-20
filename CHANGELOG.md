# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-10-20

### Added
- YARA rules from ReversingLabs (22 `Linux.*` files, MIT) and ESET (9 Linux/server family files: Ebury, Windigo,
  Kobalos, SSHDoor, Moose, Mozi, Rakos, Mumblehard; BSD 2-Clause), and Elastic's cross-platform `Multi_*` rules
  (26 files). 357 embedded rule files in total.
- False-positive gate: every enabled rule is scanned against about 16 000 clean system files in CI; `rules/disabled.txt`
  lists rules switched off with the reason.
- `--rules-dir DIR` loads a directory of extra rules (recursive); extra rules compile into a separate set.

### Changed
- The rule set is compiled at build time and embedded serialized: loading drops from about 1.1 s to 0.3 s per run,
  and a rule file that does not compile now fails the build.
- `Exhume_Fileless_Memfd_Loader` now matches on real dynamic imports (`memfd_create` + exec + network) instead of
  strings, and `Exhume_Script_Memfd_Loader` requires a script; both previously matched libc, strace, valgrind,
  python and libsystemd-shared.

## [0.2.0] - 2026-10-13

### Added
- Multithreading control: `--threads` (0 = all cores, negative = all cores minus N; default half the cores) on a
  dedicated worker pool.
- Resource governor: `--cpulimit` pauses work while system CPU is above the limit, `--minmem` skips heavy items
  when available memory is low, `--max-runtime` bounds the scan; skips are reported as limitations.
- `--lowprio` (nice 10, idle I/O class), `--soft` and automatic soft mode on 1-core or < 1 GiB RAM hosts, `--nosoft`.
- `--lookback DAYS` for the persistence, SUID and webshell modules; `--max-file-size`, `--max-region-size`,
  `--yara-timeout`.
- Scan statistics in the report (`stats`): threads, pause time, skipped items, per-phase durations.

### Changed
- Host-wide modules (rootkit cross-views, persistence + SUID sweep, webshells, package integrity) now run
  concurrently instead of one after another; the package database loads while processes are snapshotted.
- SUID/SGID sweep and web-root walk are parallel directory walks.
- YARA targets are deduplicated by device and inode and scheduled largest-first, one target per task.
- Per-process analysis is scheduled one process per task.

## [0.1.1] - 2026-10-11

### Fixed
- A named pipe (FIFO) or device file planted where Exhume reads (cron.d, systemd unit directories, profile.d,
  web roots, persistence targets, packaged files) could block the scan forever. Files are now opened
  non-blocking and read only when the opened descriptor is a regular file.

## [0.1.0] - 2026-10-11

### Added
- Process hunting: deleted and memfd-backed executables, binaries in `/tmp`, `/dev/shm`, `/var/tmp` and hidden
  directories, fake kernel-thread names (PF_KTHREAD check), daemon-name masquerading, shells and interpreters with
  network sockets on stdio, web/database servers spawning shells, obfuscated and reverse-shell command lines.
- Memory: anonymous executable and RWX mappings, ELF headers in anonymous memory, memfd mappings, libraries mapped
  from unusual paths (`/proc/<pid>/maps`, `/proc/<pid>/mem`).
- Injection: `LD_PRELOAD`/`LD_AUDIT`/`LD_LIBRARY_PATH` in process environments, `/etc/ld.so.preload`, `TracerPid`.
- Rootkit cross-views: `/proc` listing vs `kill(pid, 0)` brute force, `/proc/modules` vs `/sys/module` vs
  `/proc/kallsyms`, kernel taint decoding, known LKM rootkit names, eBPF program enumeration with owner mapping.
- Persistence: cron, anacron, at, systemd units/drop-ins/timers/generators (system and user), rc.local, init.d,
  update-motd.d, shell profiles, authorized_keys, sudoers, PAM configuration and unpackaged PAM modules, udev rules,
  XDG autostart, modprobe `install` hooks, APT hooks, extra UID 0 accounts, SUID/SGID sweep.
- Package integrity: dpkg md5sums verification (native, no external tools) and `rpm -V`.
- Webshell hunting under discovered web roots (nginx/Apache configs, Tomcat, `public_html`): PHP, JSP and CGI heuristics.
- Network: socket inventory mapped to processes via socket inodes, bind shells, backdoor ports, AF_PACKET/raw sniffers.
- YARA (yara-x) on suspicious memory regions, process images, persistence targets and web scripts with vetted
  Elastic `Linux_*` and signature-base Linux/webshell rules plus Exhume's own rules.
- Console, JSON and offline HTML reports; `--min-severity`, `--deep`, `--no-color`; exit code 2 on High/Critical.
- Static musl build and GitHub Actions CI.
