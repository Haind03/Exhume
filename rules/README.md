# YARA rules

Every rule file here is compiled at **build time** (`build.rs`) with yara-x; only the compiled, serialized rule set is
embedded in the binary. A file that does not compile fails the build, and the run-time cost of loading the rules is a
deserialization (about 0.3 s) instead of a compile. Rules you add with `--rules FILE` or `--rules-dir DIR` are compiled
at run time into a separate set and never mixed into the vetted one.

| Directory | Upstream | Pinned commit | Files | License |
| --- | --- | --- | --- | --- |
| `custom/` | Exhume | - | 1 | MIT |
| `elastic/` | [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) `yara/rules/Linux_*.yar` and `Multi_*.yar` | `955723319e62a7e4095d256355b095a7594ff48c` | 274 | Elastic License 2.0 ([LICENSE.txt](elastic/LICENSE.txt)) |
| `signature-base/` | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) `yara/` | `94a1c48d7ab499879287ff611dfe7f9c56376030` | 51 | Detection Rule License 1.1 ([LICENSE](signature-base/LICENSE)) |
| `reversinglabs/` | [reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) `yara/**/Linux.*.yara` | `e0a0be54aa1e11ccfd6854e4f19e9476f328fd84` | 22 | MIT ([LICENSE](reversinglabs/LICENSE)) |
| `eset/` | [eset/malware-ioc](https://github.com/eset/malware-ioc) Linux/server families | `705ead5a0a86fefae3c2390f91a339852384f438` | 9 | BSD 2-Clause ([LICENSE](eset/LICENSE)) |

Files are unmodified copies of upstream, with the rule authors, references and license notices intact.

## Vetting

1. **Pinned**: rules come from the commit above, not from a moving branch.
2. **Only rule files**: only `.yar`/`.yara` files were copied (no scripts, IOC lists or binaries), plus each upstream
   license.
3. **Linux relevance**:
   - Elastic: every `Linux_*.yar` file, plus the cross-platform `Multi_*.yar` files (miners, Sliver, gsocket, Mythic,
     tunnelling and other tooling that runs on Linux too).
   - signature-base: files whose names refer to Linux/ELF malware, or that test for the ELF magic
     (`uint32(0) == 0x464c457f`), plus the webshell collections used on web roots
     (`gen_webshells`, `thor-webshells`, `gen_cn_webshells`, `cn_pentestset_webshells`,
     `apt_laudanum_webshells`, `apt_webshell_chinachopper`, `webshell_regeorg`, `gen_b374k_extra`,
     `vul_php_zlib_backdoor`).
     Excluded on purpose: files that need external variables (`yara_mixed_ext_vars`, `gen_webshells_ext_vars`)
     and files that are Windows-only despite matching the filter (`apt_apt36_operation_sindoor`,
     `apt_backdoor_sunburst_fnv1a_experimental`, `gen_khepri`, `gen_fireeye_redteam_tools`,
     `exploit_cve_2022_22954_vmware_workspace_one`).
   - ReversingLabs: every `Linux.*` rule (backdoors such as BPFDoor, GTPDOOR, PygmyGoat, WolfsBane, Sshdinjector;
     rootkits such as Pumakit; Linux ransomware and wipers).
   - ESET: the Linux/server families from ESET research — Ebury and Windigo (Onimiki, Helimod), Kobalos, SSHDoor,
     Moose, Mozi, Rakos, Mumblehard. Windows-only files of the repository were not taken.
4. **Compile check**: the whole set compiles at build time with yara-x (no missing modules, no external variables).
5. **False-positive gate**: `cargo test --release -- --ignored false_positive` scans every enabled rule against the
   clean system binaries, libraries and configuration of the build host (`/usr/bin`, `/usr/sbin`, `/usr/lib`,
   `/usr/libexec`, `/etc`; about 16 000 files on an Ubuntu runner) and fails on any match. CI runs it on every change.
   A rule that cannot be fixed is listed in [`disabled.txt`](disabled.txt) with the reason; its matches are dropped.

## Licensing reminder

- Elastic License 2.0: the rules may not be provided to third parties as a hosted or managed service.
- DRL 1.1: keep the author and reference fields when sharing the rules.
- MIT (ReversingLabs) and BSD 2-Clause (ESET): keep the copyright and license notices.

Exhume ships the rule files unmodified with their licenses, and every YARA finding states the license of the rule that
produced it.
