//! `buffering.*`: what a route reads whole before passing it on (Traefik's
//! buffering middleware).

use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::BufferingConfig;
use std::collections::HashMap;

/// A size label: its bytes, or `W037` and `None` when it is not a
/// positive number.
fn size(
    labels: &HashMap<String, String>,
    key: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<u64> {
    let value = labels.get(key)?;
    match value.trim().parse::<u64>() {
        Ok(bytes) if bytes > 0 => Some(bytes),
        _ => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W037InvalidBuffering,
                    "the size is not a positive number of bytes, that body is not buffered",
                )
                .with_label(key)
                .with_value(value)
                .with_hint("give the largest body to accept, in bytes"),
            );
            None
        }
    }
}

/// Parse `buffering.maxRequestBodyBytes` and `buffering.maxResponseBodyBytes`.
/// Traefik's `memRequestBodyBytes`, `memResponseBodyBytes` and
/// `retryExpression` have no use here: `W037`. `None` when neither max is
/// usable.
pub fn parse_buffering(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<BufferingConfig> {
    let key = |name: &str| format!("{prefix}buffering.{name}");
    for (name, hint) in [
        (
            "memRequestBodyBytes",
            "Sōzune keeps the request body in memory, up to maxRequestBodyBytes",
        ),
        (
            "memResponseBodyBytes",
            "Sōzune keeps the response body in memory, up to maxResponseBodyBytes",
        ),
        (
            "retryExpression",
            "use retry.attempts, and retry.codes through the API, to retry",
        ),
    ] {
        let label = key(name);
        if let Some(value) = labels.get(&label) {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W037InvalidBuffering,
                    format!("buffering.{name} has no equivalent, dropped"),
                )
                .with_label(&label)
                .with_value(value)
                .with_hint(hint),
            );
        }
    }
    let config = BufferingConfig {
        max_request_body_bytes: size(labels, &key("maxRequestBodyBytes"), diagnostics),
        max_response_body_bytes: size(labels, &key("maxResponseBodyBytes"), diagnostics),
    };
    (config != BufferingConfig::default()).then_some(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(pairs: &[(&str, &str)]) -> (Option<BufferingConfig>, Vec<Diagnostic>) {
        let labels = pairs
            .iter()
            .map(|(k, v)| (format!("sozune.http.up.{k}"), v.to_string()))
            .collect();
        let mut diagnostics = Vec::new();
        let config = parse_buffering(&labels, "sozune.http.up.", &mut diagnostics);
        (config, diagnostics)
    }

    #[test]
    fn the_sizes_make_the_buffering() {
        let (config, diagnostics) = parse(&[
            ("buffering.maxRequestBodyBytes", "1048576"),
            ("buffering.maxResponseBodyBytes", "2000"),
        ]);
        assert!(diagnostics.is_empty());
        assert_eq!(
            config.unwrap(),
            BufferingConfig {
                max_request_body_bytes: Some(1_048_576),
                max_response_body_bytes: Some(2000),
            }
        );
        let (config, _) = parse(&[("buffering.maxRequestBodyBytes", "10")]);
        assert_eq!(config.unwrap().max_response_body_bytes, None);
    }

    #[test]
    fn no_label_is_no_buffering() {
        assert_eq!(parse(&[]), (None, Vec::new()));
    }

    #[test]
    fn a_size_that_is_not_one_is_reported() {
        for bad in ["0", "-1", "1MB", ""] {
            let (config, diagnostics) = parse(&[("buffering.maxRequestBodyBytes", bad)]);
            assert!(config.is_none(), "{bad}");
            assert_eq!(diagnostics[0].code, DiagnosticCode::W037InvalidBuffering);
        }
    }

    /// Traefik's options Sōzune has no use for are reported, the rest kept.
    #[test]
    fn traefik_options_without_equivalent_are_reported() {
        let (config, diagnostics) = parse(&[
            ("buffering.maxRequestBodyBytes", "100"),
            ("buffering.memRequestBodyBytes", "50"),
            ("buffering.memResponseBodyBytes", "50"),
            (
                "buffering.retryExpression",
                "IsNetworkError() && Attempts() < 2",
            ),
        ]);
        assert_eq!(config.unwrap().max_request_body_bytes, Some(100));
        assert_eq!(diagnostics.len(), 3);
    }
}
