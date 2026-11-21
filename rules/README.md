# YARA rules

Every rule file here is compiled at **build time** (`build.rs`) with yara-x; only the compiled, serialized rule set is
embedded in the binary. A file that does not compile fails the build, and the run-time cost of loading the rules is a
deserialization (about 0.3 s) instead of a compile. Rules you add with `--rules FILE` or `--rules-dir DIR` are compiled
at run time into a separate set and never mixed into the vetted one.

| Directory | Upstream | Pinned commit | Files | License |
| --- | --- | --- | --- | --- |
| `custom/` | Exhume | - | 1 | MIT |
| `elastic/` | [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) `yara/rules/Linux_*.yar` and `Multi_*.yar` | `955723319e62a7e4095d256355b095a7594ff48c` | 274 | Elastic License 2.0 ([LICENSE.txt](elastic/LICENSE.txt)) |
| `signature-base/` | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) `yara/` | `78d979eef87786a613659ee82e55abdd45572a78` | 51 | Detection Rule License 1.1 ([LICENSE](signature-base/LICENSE)) |
| `reversinglabs/` | [reversinglabs/reversinglabs-yara-rules](https://github.com/reversinglabs/reversinglabs-yara-rules) `yara/**/Linux.*.yara` | `e0a0be54aa1e11ccfd6854e4f19e9476f328fd84` | 22 | MIT ([LICENSE](reversinglabs/LICENSE)) |
| `eset/` | [eset/malware-ioc](https://github.com/eset/malware-ioc) Linux/server families | `705ead5a0a86fefae3c2390f91a339852384f438` | 9 | BSD 2-Clause ([LICENSE](eset/LICENSE)) |
| `sekoia/` | [SEKOIA-IO/Community](https://github.com/SEKOIA-IO/Community) `yara_rules/` | `ae52d3fed661f7459c3877fec630e66a1771d5d0` | 80 | Detection Rule License 1.1 ([LICENSE.md](sekoia/LICENSE.md)) |
| `volexity/` | [volexity/threat-intel](https://github.com/volexity/threat-intel) per-report rule files | `683296427d8c7f08938ce6c587f618c938cf4c54` | 9 | BSD 2-Clause ([LICENSE.txt](volexity/LICENSE.txt)) |
| `jpcert/` | [JPCERTCC/jpcert-yara](https://github.com/JPCERTCC/jpcert-yara) | `7837438e7bcb100bcc7f9d2be09152b19d967c0c` | 16 | BSD 3-Clause ([LICENSE](jpcert/LICENSE)) |
| `tenable/` | [tenable/yara-rules](https://github.com/tenable/yara-rules) | `e7e0a8947c3a798ee2f2b44f0c1b6fd0f8a0daba` | 8 | BSD 3-Clause ([LICENSE.md](tenable/LICENSE.md)) |
| `mandiant/` | [mandiant/red_team_tool_countermeasures](https://github.com/mandiant/red_team_tool_countermeasures) | `3561b71724dbfa3e2bb78106aaa2d7f8b892c43b` | 2 | BSD 2-Clause ([LICENSE.txt](mandiant/LICENSE.txt)) |
| `intezer/` | [intezer/yara-rules](https://github.com/intezer/yara-rules) | `e83de8d7143607c2c056f6c2d0a494a001b4dbfa` | 1 | MIT ([LICENSE](intezer/LICENSE)) |
| `trellix/` | [advanced-threat-research/Yara-Rules](https://github.com/advanced-threat-research/Yara-Rules) | `1919562a59f190bda60c982424f6a24c542ee3e0` | 1 | Apache 2.0 ([LICENSE](trellix/LICENSE)) |
| `bartblaze/` | [bartblaze/Yara-rules](https://github.com/bartblaze/Yara-rules) | `5cc871d82361de8a80d387ec8bbd01fe4258b4a9` | 1 | MIT ([LICENSE](bartblaze/LICENSE)) |

Files are unmodified copies of upstream, with the rule authors, references and license notices intact. Volexity
publishes one `rules.yar`/`yara.yar` per report, so those files are stored under the report date and name
(`2024-06-13_DISGOMOJI.yar`). One upstream file uses the `math` module without importing it
(`volexity/2022-06-15_DriftingCloud_Sophos.yar`); `build.rs` supplies the import at compile time
(`MISSING_IMPORTS`) instead of editing the file.

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
   - SEKOIA: every rule file whose condition tests for an ELF file (Linux backdoors, rootkits, botnets, miners,
     privilege-escalation exploits, Linux variants of APT implants), the cross-platform tunnelling and C2 tools
     (Sliver, Chisel, Ligolo, gost, Stowaway, Venom, Supershell, fscan, rathole, gsocket, ...) and the webshell
     rules (b374k, WSO, Weevely, IceSword, Pivotnacci, generic PHP). Left out: Windows-only tools and families
     (Potato exploits, SafetyKatz, RunasCs, PlugX, Dark Pink, Mustang Panda, ...), IIS/ASPX webshells, and tools
     that are ordinary distribution packages and would flag admin hosts (`socat`, `nping`, `iodine`, `3proxy`,
     `microsocks`).
   - Volexity: reports on Linux, edge appliances and Java/PHP webshells: BRICKSTORM/VerdantBamboo, SonicWall
     (OrangeTail, RootRun), Ivanti Connect Secure (2024 and 2026), Palo Alto GlobalProtect (UPSTYLE), DISGOMOJI,
     Confluence (CVE-2022-26134), Sophos Firewall (DriftingCloud), Zimbra (CVE-2022-27925).
   - JPCERT/CC: PHP webshells (b374k, FilesMan, PHP File Manager, fox WSO, CVE-2021-20837, Water Pamola, SEO
     spam kits), Ivanti/Pulse Secure implants, FortiGate and Barracuda (SEASPY) implants, SysrvBot, StealthWorker,
     GobRAT, UNC5174 and anti-UPX-unpacking ELF.
   - Tenable: ELF format anomalies, Kaiten and Venom, PHP/JSP webshells (PAS, FOPO, PBot, obfuscated PHP).
   - Mandiant: REDFLARE Linux implant and controller. Intezer: EvilGnome. Trellix: HelloKitty Linux
     ransomware. bartblaze: PHP code hidden in image files.
   - ESET: the Linux/server families from ESET research — Ebury and Windigo (Onimiki, Helimod), Kobalos, SSHDoor,
     Moose, Mozi, Rakos, Mumblehard. Windows-only files of the repository were not taken.
4. **Compile check**: the whole set compiles at build time with yara-x (no missing modules, no external variables).
5. **False-positive gate**: `cargo test --release -- --ignored false_positive` scans every enabled rule against
   clean files and fails on any match. By default the corpus is the build host's `/usr/bin`, `/usr/sbin`,
   `/usr/lib`, `/usr/libexec` and `/etc`; `EXHUME_FP_ROOTS` (colon-separated) changes it. CI adds `/usr/share`,
   `/usr/local` and `/opt`, which on a GitHub runner hold the preinstalled toolchains (Node.js, Python, Go, Java,
   .NET, browsers, cloud CLIs). Locally, 111 298 files (system, `/usr/share`, `/opt`, the cargo registry and the
   Rust toolchain) produced no match with the current set.
   A rule that cannot be fixed is listed in [`disabled.txt`](disabled.txt) with the reason; its matches are dropped.

## Licensing reminder

- Elastic License 2.0: the rules may not be provided to third parties as a hosted or managed service.
- DRL 1.1: keep the author and reference fields when sharing the rules.
- DRL 1.1 also applies to the SEKOIA rules.
- MIT (ReversingLabs, Intezer, bartblaze), BSD 2-Clause (ESET, Volexity, Mandiant), BSD 3-Clause (JPCERT/CC,
  Tenable): keep the copyright and license notices.
- Apache 2.0 (Trellix): keep the license and any notices.

Exhume ships the rule files unmodified with their licenses, and every YARA finding states the license of the rule that
produced it.
