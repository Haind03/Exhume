# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

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
