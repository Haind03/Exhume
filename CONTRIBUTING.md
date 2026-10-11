# Contributing to Exhume

Thanks for helping. Exhume is a read-only live-response tool, so the bar is: **no host modification, no
false sense of security, tests for every rule.**

## Layout

| Path | Contents |
| --- | --- |
| `src/core` | Platform-independent detection logic on plain data. Every rule lives here and is unit-tested. |
| `src/linux` | Collectors: `/proc`, `/sys`, the `bpf(2)` syscall, package databases, filesystem walks. No scoring logic. |
| `src/rules.rs`, `build.rs` | Embedding of the YARA rule set into the binary. |
| `rules/custom` | Exhume's own YARA rules (MIT). |
| `rules/elastic`, `rules/signature-base` | Vendored third-party rules, pinned, with their original licenses. |

## Workflow

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test                         # includes compile-checking every embedded YARA file
cargo test --no-default-features   # core logic without the YARA engine
sudo ./target/release/exhume --deep --html /tmp/r.html
```

## Adding a detection

1. Put the decision logic in `src/core` as a pure function over data (strings, structs), not over the live system.
2. Add unit tests for a true positive **and** for the benign look-alikes you thought about.
3. Map it to MITRE ATT&CK technique IDs and update the coverage table in the README.
4. Collect the data in `src/linux` with read-only calls. Degrade gracefully when not root.

## Updating vendored YARA rules

1. Pin a new upstream commit and record it in `rules/README.md` and the README.
2. Copy only `.yar` files; keep the upstream `LICENSE` next to them.
3. `cargo test linux::yara` must pass: every file is compiled on its own with yara-x.

## Commit style

Short imperative subject (`Add udev RUN+= scoring`), body explaining *why*.
