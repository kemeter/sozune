use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::RateLimitConfig;
use std::collections::HashMap;

/// Parse the `ratelimit.average` and `ratelimit.burst` labels.
///
/// - Both absent → returns `None` quietly.
/// - Only average set → burst defaults to average.
/// - Only burst set → invalid (no average means no rate limit), emits `W004`.
/// - Either one non-numeric → emits `W004` and returns `None`.
pub fn parse_rate_limit(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<RateLimitConfig> {
    let avg_key = format!("{prefix}ratelimit.average");
    let burst_key = format!("{prefix}ratelimit.burst");
    let avg_raw = labels.get(&avg_key);
    let burst_raw = labels.get(&burst_key);

    if avg_raw.is_none() && burst_raw.is_none() {
        return None;
    }

    let average = match avg_raw {
        None => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W004InvalidRateLimit,
                    "ratelimit.burst set without ratelimit.average, ignoring",
                )
                .with_label(&avg_key)
                .with_hint("set ratelimit.average to enable rate limiting"),
            );
            return None;
        }
        Some(raw) => match raw.parse::<u64>() {
            Ok(n) => n,
            Err(_) => {
                diagnostics.push(
                    Diagnostic::new(
                        DiagnosticCode::W004InvalidRateLimit,
                        "ratelimit.average is not a valid integer, rate limit disabled",
                    )
                    .with_label(&avg_key)
                    .with_value(raw),
                );
                return None;
            }
        },
    };

    let burst = match burst_raw {
        None => average,
        Some(raw) => match raw.parse::<u64>() {
            Ok(n) => n,
            Err(_) => {
                diagnostics.push(
                    Diagnostic::new(
                        DiagnosticCode::W004InvalidRateLimit,
                        "ratelimit.burst is not a valid integer, falling back to average",
                    )
                    .with_label(&burst_key)
                    .with_value(raw),
                );
                average
            }
        },
    };

    Some(RateLimitConfig { average, burst })
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
    fn absent_returns_none_quietly() {
        let mut diags = Vec::new();
        assert!(parse_rate_limit(&labels(&[]), "sozune.http.web.", &mut diags).is_none());
        assert!(diags.is_empty());
    }

    #[test]
    fn average_only_uses_average_as_burst() {
        let mut diags = Vec::new();
        let r = parse_rate_limit(
            &labels(&[("sozune.http.web.ratelimit.average", "100")]),
            "sozune.http.web.",
            &mut diags,
        )
        .unwrap();
        assert_eq!(r.average, 100);
        assert_eq!(r.burst, 100);
        assert!(diags.is_empty());
    }

    #[test]
    fn average_and_burst_used_when_both_set() {
        let mut diags = Vec::new();
        let r = parse_rate_limit(
            &labels(&[
                ("sozune.http.web.ratelimit.average", "100"),
                ("sozune.http.web.ratelimit.burst", "200"),
            ]),
            "sozune.http.web.",
            &mut diags,
        )
        .unwrap();
        assert_eq!(r.average, 100);
        assert_eq!(r.burst, 200);
    }

    #[test]
    fn burst_without_average_emits_w004() {
        let mut diags = Vec::new();
        assert!(parse_rate_limit(
            &labels(&[("sozune.http.web.ratelimit.burst", "200")]),
            "sozune.http.web.",
            &mut diags,
        )
        .is_none());
        assert_eq!(diags[0].code, DiagnosticCode::W004InvalidRateLimit);
    }

    #[test]
    fn invalid_average_emits_w004() {
        let mut diags = Vec::new();
        assert!(parse_rate_limit(
            &labels(&[("sozune.http.web.ratelimit.average", "abc")]),
            "sozune.http.web.",
            &mut diags,
        )
        .is_none());
        assert_eq!(diags[0].code, DiagnosticCode::W004InvalidRateLimit);
    }

    #[test]
    fn invalid_burst_falls_back_to_average() {
        let mut diags = Vec::new();
        let r = parse_rate_limit(
            &labels(&[
                ("sozune.http.web.ratelimit.average", "50"),
                ("sozune.http.web.ratelimit.burst", "loads"),
            ]),
            "sozune.http.web.",
            &mut diags,
        )
        .unwrap();
        assert_eq!(r.average, 50);
        assert_eq!(r.burst, 50);
        assert_eq!(diags[0].code, DiagnosticCode::W004InvalidRateLimit);
    }
}
