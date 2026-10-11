# YARA rules

All files here are embedded into the Exhume binary at build time (`build.rs`) and compiled with yara-x at run
time, only when there is something suspicious to scan. Every file is compile-checked on its own in CI
(`linux::yara::tests::embedded_rules_compile`).

| Directory | Upstream | Pinned commit | Files | License |
| --- | --- | --- | --- | --- |
| `custom/` | Exhume | - | 1 | MIT |
| `elastic/` | [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) `yara/rules/Linux_*.yar` | `955723319e62a7e4095d256355b095a7594ff48c` | 248 | Elastic License 2.0 ([LICENSE.txt](elastic/LICENSE.txt)) |
| `signature-base/` | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) `yara/` | `94a1c48d7ab499879287ff611dfe7f9c56376030` | 51 | Detection Rule License 1.1 ([LICENSE](signature-base/LICENSE)) |

Files are unmodified copies of upstream, with the rule authors, references and license notices intact.

## Vetting

1. **Pinned**: rules come from the commit above, not from a moving branch.
2. **Only rule files**: only `.yar` files were copied (no scripts, IOC lists or binaries), plus each upstream license.
3. **Linux relevance**:
   - Elastic: every `Linux_*.yar` file.
   - signature-base: files whose names refer to Linux/ELF malware, or that test for the ELF magic
     (`uint32(0) == 0x464c457f`), plus the webshell collections used on web roots
     (`gen_webshells`, `thor-webshells`, `gen_cn_webshells`, `cn_pentestset_webshells`,
     `apt_laudanum_webshells`, `apt_webshell_chinachopper`, `webshell_regeorg`, `gen_b374k_extra`,
     `vul_php_zlib_backdoor`).
   - Excluded on purpose: files that need external variables (`yara_mixed_ext_vars`, `gen_webshells_ext_vars`)
     and files that are Windows-only despite matching the filter (`apt_apt36_operation_sindoor`,
     `apt_backdoor_sunburst_fnv1a_experimental`, `gen_khepri`, `gen_fireeye_redteam_tools`,
     `exploit_cve_2022_22954_vmware_workspace_one`).
4. **Compile check**: each file compiles standalone with yara-x (no missing modules, no external variables).

## Licensing reminder

The Elastic License 2.0 does not allow providing the rules to third parties as a hosted or managed service.
The DRL 1.1 requires keeping the author and reference fields when sharing the rules. Exhume ships both files
unmodified and reports the license of the rule behind every YARA match.
