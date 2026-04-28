use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::{PathConfig, PathRuleType};
use std::collections::HashMap;

/// Parse path configuration from the three possible labels: `path`, `prefix`,
/// `pathRegex`. Precedence: `path` > `prefix` > `pathRegex`. When none is set,
/// defaults to `Prefix("/")` and emits `I001`.
pub fn parse_path(
    labels: &HashMap<String, String>,
    prefix_key: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> PathConfig {
    let exact = labels.get(&format!("{prefix_key}path"));
    let prefix = labels.get(&format!("{prefix_key}prefix"));
    let regex = labels.get(&format!("{prefix_key}pathRegex"));

    match (exact, prefix, regex) {
        (Some(p), _, _) => PathConfig {
            rule_type: PathRuleType::Prefix,
            value: p.clone(),
        },
        (None, Some(p), _) => PathConfig {
            rule_type: PathRuleType::Prefix,
            value: p.clone(),
        },
        (None, None, Some(r)) => PathConfig {
            rule_type: PathRuleType::Regex,
            value: r.clone(),
        },
        (None, None, None) => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::I001PathDefaulted,
                    "no path/prefix/pathRegex label, defaulting to prefix \"/\"",
                )
                .with_label(format!("{prefix_key}path|prefix|pathRegex")),
            );
            PathConfig {
                rule_type: PathRuleType::Prefix,
                value: "/".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn explicit_path_wins_over_prefix() {
        let mut diags = Vec::new();
        let p = parse_path(
            &labels(&[
                ("sozune.http.web.path", "/api"),
                ("sozune.http.web.prefix", "/legacy"),
            ]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(p.rule_type, PathRuleType::Prefix);
        assert_eq!(p.value, "/api");
        assert!(diags.is_empty());
    }

    #[test]
    fn prefix_used_when_path_absent() {
        let mut diags = Vec::new();
        let p = parse_path(
            &labels(&[("sozune.http.web.prefix", "/v1")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(p.rule_type, PathRuleType::Prefix);
        assert_eq!(p.value, "/v1");
    }

    #[test]
    fn regex_used_when_only_regex_set() {
        let mut diags = Vec::new();
        let p = parse_path(
            &labels(&[("sozune.http.web.pathRegex", r"^/api/v\d+/.*")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(p.rule_type, PathRuleType::Regex);
        assert_eq!(p.value, r"^/api/v\d+/.*");
    }

    #[test]
    fn no_path_defaults_to_root_and_emits_i001() {
        let mut diags = Vec::new();
        let p = parse_path(&labels(&[]), "sozune.http.web.", &mut diags);
        assert_eq!(p.rule_type, PathRuleType::Prefix);
        assert_eq!(p.value, "/");
        assert_eq!(diags[0].code, DiagnosticCode::I001PathDefaulted);
    }
}
