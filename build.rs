//! Embeds every vetted YARA rule file under `rules/` into the binary, so the static build carries
//! its rule set with it (no files to drop on the host under investigation).

use std::fmt::Write as _;
use std::path::Path;
use std::{env, fs};

const SOURCES: &[&str] = &["custom", "elastic", "signature-base"];

fn main() {
    println!("cargo:rerun-if-changed=rules");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
    let mut out = String::from("pub static EMBEDDED: &[(&str, &str, &str)] = &[\n");
    for src in SOURCES {
        let dir = root.join(src);
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        let mut files: Vec<_> = rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yar" | "yara")))
            .collect();
        files.sort();
        for f in files {
            let name = f.file_name().unwrap().to_string_lossy().into_owned();
            writeln!(
                out,
                "    ({src:?}, {name:?}, include_str!({:?})),",
                f.display().to_string()
            )
            .unwrap();
        }
    }
    out.push_str("];\n");
    let dest = Path::new(&env::var("OUT_DIR").unwrap()).join("embedded_rules.rs");
    fs::write(dest, out).unwrap();
}
