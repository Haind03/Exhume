# Security Policy

Exhume is a defensive tool that runs as root on hosts that may already be compromised, so bugs in it matter.

## Supported versions

Only the latest release receives fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems in Exhume itself (for example: a crafted file
or process name that crashes the scanner, makes it hang, escapes the HTML report, or causes it to modify the host).

Report privately through GitHub's *Report a vulnerability* button (Security tab → Advisories), or by email to
**haind@ptit.edu.vn**. Include the version (`exhume --version`), the distribution and kernel, and a minimal
reproduction. You should receive an acknowledgement within 7 days.

## Scope notes

- Detection gaps (malware Exhume does not find) are normal bugs: open an issue or a pull request with a test.
- Exhume reads `/proc/<pid>/mem` with `pread` and never writes to it, never signals processes (it uses
  `kill(pid, 0)`, which delivers no signal) and never changes files. Anything that breaks this promise is a
  security bug.
