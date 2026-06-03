use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use std::collections::HashMap;

/// Parse the `inFlightReq` label — the maximum number of concurrent in-flight
/// requests per client IP for the route.
///
/// - Absent → returns `None` quietly (limiter disabled).
/// - A positive integer → `Some(n)`.
/// - Non-numeric or zero → emits `W025` and returns `None`.
pub fn parse_in_flight_req(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<u64> {
    let key = format!("{prefix}inFlightReq");
    let raw = labels.get(&key)?;

    match raw.parse::<u64>() {
        Ok(n) if n > 0 => Some(n),
        Ok(_) => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W025InvalidInFlightReq,
                    "inFlightReq must be a positive integer, in-flight limiter disabled",
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint("set inFlightReq to a value of 1 or more"),
            );
            None
        }
        Err(_) => {
            diagnostics.push(
                Diagnostic::new(
                    DiagnosticCode::W025InvalidInFlightReq,
                    "inFlightReq is not a valid integer, in-flight limiter disabled",
                )
                .with_label(&key)
                .with_value(raw)
                .with_hint(
                    "set inFlightReq to a positive integer (max concurrent requests per IP)",
                ),
            );
            None
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
    fn absent_returns_none_quietly() {
        let mut diags = Vec::new();
        assert!(parse_in_flight_req(&labels(&[]), "sozune.http.web.", &mut diags).is_none());
        assert!(diags.is_empty());
    }

    #[test]
    fn valid_value_parses() {
        let mut diags = Vec::new();
        let n = parse_in_flight_req(
            &labels(&[("sozune.http.web.inFlightReq", "10")]),
            "sozune.http.web.",
            &mut diags,
        );
        assert_eq!(n, Some(10));
        assert!(diags.is_empty());
    }

    #[test]
    fn invalid_value_emits_w025() {
        let mut diags = Vec::new();
        assert!(
            parse_in_flight_req(
                &labels(&[("sozune.http.web.inFlightReq", "abc")]),
                "sozune.http.web.",
                &mut diags,
            )
            .is_none()
        );
        assert_eq!(diags[0].code, DiagnosticCode::W025InvalidInFlightReq);
    }

    #[test]
    fn zero_emits_w025() {
        let mut diags = Vec::new();
        assert!(
            parse_in_flight_req(
                &labels(&[("sozune.http.web.inFlightReq", "0")]),
                "sozune.http.web.",
                &mut diags,
            )
            .is_none()
        );
        assert_eq!(diags[0].code, DiagnosticCode::W025InvalidInFlightReq);
    }
}
