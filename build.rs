//! Bakes the vetted YARA rule set under `rules/` into the binary. With the `yara` feature the
//! rules are compiled here, at build time, and only the serialized result is embedded: the static
//! binary carries its rules (nothing is dropped on the host under investigation) and starts
//! scanning without a compile step. A rule file that does not compile fails the build.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

const SOURCES: &[&str] = &[
    "custom",
    "elastic",
    "signature-base",
    "reversinglabs",
    "eset",
];

fn rule_files(root: &Path) -> Vec<(String, String, PathBuf)> {
    let mut v = Vec::new();
    for src in SOURCES {
        let Ok(rd) = fs::read_dir(root.join(src)) else {
            continue;
        };
        let mut files: Vec<PathBuf> = rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yar" | "yara")))
            .collect();
        files.sort();
        for f in files {
            let name = f.file_name().unwrap().to_string_lossy().into_owned();
            v.push((src.to_string(), name, f));
        }
    }
    v
}

fn main() {
    println!("cargo:rerun-if-changed=rules");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let files = rule_files(&root);

    let mut code = String::from("/// (source, rule file) of every embedded rule file.\npub static EMBEDDED: &[(&str, &str)] = &[\n");
    for (src, name, _) in &files {
        writeln!(code, "    ({src:?}, {name:?}),").unwrap();
    }
    code.push_str("];\n");
    fs::write(out_dir.join("embedded_rules.rs"), code).unwrap();

    #[cfg(feature = "yara")]
    compile(&files, &out_dir);
}

#[cfg(feature = "yara")]
fn compile(files: &[(String, String, PathBuf)], out_dir: &Path) {
    let mut c = yara_x::Compiler::new();
    for (src, name, path) in files {
        let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        c.new_namespace(&format!("{src}/{name}"));
        if let Err(e) = c.add_source(text.as_str()) {
            panic!("YARA rule file {src}/{name} does not compile:\n{e}");
        }
    }
    let rules = c.build();
    let bytes = rules.serialize().expect("serialize compiled YARA rules");
    fs::write(out_dir.join("rules.bin"), bytes).unwrap();
}
