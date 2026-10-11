//! The embedded YARA rule set (see build.rs) and how its matches are rated.

use crate::core::report::Severity;

include!(concat!(env!("OUT_DIR"), "/embedded_rules.rs"));

/// License of each vendored rule source.
pub fn license(source: &str) -> &'static str {
    match source {
        "elastic" => "Elastic License 2.0 (rules/elastic/LICENSE.txt)",
        "signature-base" => "Detection Rule License 1.1 (rules/signature-base/LICENSE)",
        "custom" => "MIT (Exhume)",
        _ => "user supplied",
    }
}

/// Severity of a rule match from its source and metadata (`score`/`severity`), bumped when the
/// match sits in memory that was already suspicious.
pub fn severity_for(
    source: &str,
    score: Option<i64>,
    sev_str: Option<&str>,
    in_memory: bool,
) -> Severity {
    let base = if let Some(s) = sev_str.and_then(Severity::parse) {
        s
    } else if let Some(n) = score {
        match n {
            80.. => Severity::High,
            50..=79 => Severity::Medium,
            _ => Severity::Low,
        }
    } else if source == "elastic" {
        Severity::High
    } else {
        Severity::Medium
    };
    if in_memory && base == Severity::Medium {
        Severity::High
    } else {
        base
    }
}

pub fn counts() -> Vec<(&'static str, usize)> {
    let mut v: Vec<(&'static str, usize)> = Vec::new();
    for (src, _, _) in EMBEDDED {
        match v.iter_mut().find(|(s, _)| s == src) {
            Some(e) => e.1 += 1,
            None => v.push((src, 1)),
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_mapping() {
        assert_eq!(
            severity_for("elastic", Some(100), None, false),
            Severity::High
        );
        assert_eq!(
            severity_for("signature-base", Some(60), None, false),
            Severity::Medium
        );
        assert_eq!(
            severity_for("signature-base", Some(60), None, true),
            Severity::High
        );
        assert_eq!(
            severity_for("signature-base", Some(40), None, false),
            Severity::Low
        );
        assert_eq!(
            severity_for("custom", None, Some("critical"), false),
            Severity::Critical
        );
        assert_eq!(
            severity_for("signature-base", None, None, false),
            Severity::Medium
        );
    }

    #[test]
    fn embedded_sources_present() {
        let c = counts();
        for s in ["custom", "elastic", "signature-base"] {
            assert!(
                c.iter().any(|(n, k)| *n == s && *k > 0),
                "{s} missing: {c:?}"
            );
        }
        assert!(EMBEDDED.iter().all(
            |(s, f, _)| !license(s).is_empty() && (f.ends_with(".yar") || f.ends_with(".yara"))
        ));
    }
}
