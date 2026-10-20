//! The embedded YARA rule set (see build.rs) and how its matches are rated.

use crate::core::report::Severity;

include!(concat!(env!("OUT_DIR"), "/embedded_rules.rs"));

/// Rules disabled after false-positive testing (rules/disabled.txt).
static DISABLED: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/rules/disabled.txt"));

/// Parse the disabled list: (namespace or "*", rule name).
pub fn parse_disabled(text: &str) -> Vec<(&str, &str)> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some((it.next()?, it.next()?))
        })
        .collect()
}

pub fn is_disabled(namespace: &str, rule: &str) -> bool {
    parse_disabled(DISABLED)
        .iter()
        .any(|(ns, r)| *r == rule && (*ns == "*" || *ns == namespace))
}

/// License of each vendored rule source.
pub fn license(source: &str) -> &'static str {
    match source {
        "elastic" => "Elastic License 2.0 (rules/elastic/LICENSE.txt)",
        "signature-base" => "Detection Rule License 1.1 (rules/signature-base/LICENSE)",
        "reversinglabs" => "MIT (rules/reversinglabs/LICENSE)",
        "eset" => "BSD 2-Clause (rules/eset/LICENSE)",
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
    for (src, _) in EMBEDDED {
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
    fn disabled_list() {
        let t = "# c\nsignature-base/x.yar  Bad_Rule  # fp on bash\n* Other\n\n";
        assert_eq!(
            parse_disabled(t),
            vec![("signature-base/x.yar", "Bad_Rule"), ("*", "Other")]
        );
        assert!(!is_disabled(
            "custom/exhume_linux.yar",
            "Exhume_Reverse_Shell_Oneliner"
        ));
    }

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
        for s in [
            "custom",
            "elastic",
            "signature-base",
            "reversinglabs",
            "eset",
        ] {
            assert!(
                c.iter().any(|(n, k)| *n == s && *k > 0),
                "{s} missing: {c:?}"
            );
        }
        assert!(EMBEDDED
            .iter()
            .all(|(s, f)| !license(s).is_empty() && (f.ends_with(".yar") || f.ends_with(".yara"))));
    }
}
