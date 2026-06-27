//! Shared helpers for custom HTTP error pages.
//!
//! Two layers consume this module:
//! * the static config (listener-level defaults, entrypoint-level overrides) —
//!   accepts both inline bodies and `file://` references, resolved through
//!   `sozu_command_lib::config::load_answers`;
//! * provider labels (Docker / Swarm / Kubernetes) — inline bodies only,
//!   `file://` is refused to prevent a non-trusted workload from reading
//!   arbitrary host files into a response body.
//!
//! Sōzu expects each template to be a full HTTP/1.1 response
//! (`HTTP/1.1 <code> <reason>\r\n<headers>\r\n\r\n<body>`). To keep the user
//! surface simple, this module wraps any value that doesn't already start
//! with `HTTP/` into a minimal HTTP/1.1 response with `Content-Length` and
//! `Content-Type: text/html; charset=utf-8`.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer};

/// HTTP status codes that Sōzu's `CustomHttpAnswers` proto supports.
/// Anything outside this list is silently ignored by the worker, so we
/// validate up-front and emit a warning rather than dropping it on the
/// floor.
pub const SUPPORTED_STATUS_CODES: &[&str] = &[
    "301", "400", "401", "404", "408", "413", "421", "429", "502", "503", "504", "507",
];

/// Returns true if `code` is a status Sōzu knows how to template.
pub fn is_supported_status(code: &str) -> bool {
    SUPPORTED_STATUS_CODES.contains(&code)
}

/// Map a numeric HTTP status code (as a string) to the reason phrase Sōzu
/// uses in its default templates. Unknown codes fall back to "Custom" — the
/// status line still parses, the body is still served.
fn reason_phrase(code: &str) -> &'static str {
    match code {
        "301" => "Moved Permanently",
        "400" => "Bad Request",
        "401" => "Unauthorized",
        "404" => "Not Found",
        "408" => "Request Timeout",
        "413" => "Payload Too Large",
        "421" => "Misdirected Request",
        "429" => "Too Many Requests",
        "502" => "Bad Gateway",
        "503" => "Service Unavailable",
        "504" => "Gateway Timeout",
        "507" => "Insufficient Storage",
        _ => "Custom",
    }
}

/// Wrap an error-page value into a full HTTP/1.1 response Sōzu can parse.
///
/// The value may be:
/// * a `file://` reference — the file is read off disk and its contents are
///   treated exactly like an inline value (wrapped unless they already are a
///   full `HTTP/` response). This keeps a `file://` template authored as plain
///   HTML working: Sōzu itself does not wrap file contents, so without this the
///   raw HTML would reach the worker without a status line and the listener
///   would fail to load. Only trusted static config reaches here; provider
///   labels have their `file://` values stripped by
///   [`sanitize_provider_error_pages`] beforehand.
/// * an inline body already starting with `HTTP/` — passed through unchanged.
/// * any other inline body — wrapped.
///
/// The wrapped response carries `Content-Length`, `Content-Type: text/html`
/// and `Connection: close` to match the shape of Sōzu's built-in templates.
/// A `file://` whose path cannot be read falls back to wrapping the literal
/// value, so a typo surfaces as a visible body rather than a panic.
pub fn wrap_body_into_http_response(code: &str, value: &str) -> String {
    let body = match value.strip_prefix("file://") {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(e) => {
                tracing::warn!("error_pages: failed to read '{path}' (code {code}): {e}");
                value.to_string()
            }
        },
        None => value.to_string(),
    };

    if body.starts_with("HTTP/") {
        return body;
    }

    // Sōzu re-parses the template and normalizes every line ending to CRLF
    // (`\r\n` -> `\n` -> `\r\n`) before serving it. Normalize the body the same
    // way here so the `Content-Length` we emit matches the byte count Sōzu will
    // actually put on the wire. Counting the LF-form length instead would
    // under-report by one byte per line and Sōzu would truncate the tail.
    let body = body.replace("\r\n", "\n").replace('\n', "\r\n");

    let reason = reason_phrase(code);
    format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Length: {len}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        code = code,
        reason = reason,
        len = body.len(),
        body = body,
    )
}

/// Deserializer used by static config (YAML). Accepts both inline literals
/// and `file://` references. Validation of the status code happens at
/// build time when we actually push the map to Sōzu so that a typo in
/// `config.yaml` produces a diagnostic and not a silent drop.
pub fn deserialize_error_pages<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let map = BTreeMap::<String, String>::deserialize(deserializer)?;
    Ok(map)
}

/// Filter an `error_pages` map coming from a non-trusted source (provider
/// labels). Inline bodies are kept verbatim, `file://` values are dropped.
/// Unsupported status codes are also dropped. Returns the cleaned map and
/// a list of human-readable warnings describing what was filtered.
pub fn sanitize_provider_error_pages(
    raw: &BTreeMap<String, String>,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut out = BTreeMap::new();
    let mut warnings = Vec::new();

    for (code, value) in raw {
        if !is_supported_status(code) {
            warnings.push(format!(
                "error_pages: status '{code}' is not supported by sozu, ignored"
            ));
            continue;
        }
        if value.starts_with("file://") {
            warnings.push(format!(
                "error_pages: file:// is refused for provider labels (code {code}), ignored"
            ));
            continue;
        }
        out.insert(code.clone(), value.clone());
    }

    (out, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn supported_codes_match_sozu_proto() {
        // If Sōzu adds or removes a code in CustomHttpAnswers, this list
        // must be updated. Spot-check a few known entries.
        assert!(is_supported_status("404"));
        assert!(is_supported_status("503"));
        assert!(is_supported_status("421"));
        assert!(is_supported_status("429"));
        assert!(!is_supported_status("418"));
        assert!(!is_supported_status("200"));
    }

    #[test]
    fn provider_inline_value_passes_through() {
        let (out, warnings) = sanitize_provider_error_pages(&m(&[("503", "<h1>Down</h1>")]));
        assert_eq!(out.get("503"), Some(&"<h1>Down</h1>".to_string()));
        assert!(warnings.is_empty());
    }

    #[test]
    fn provider_file_uri_is_refused() {
        let (out, warnings) = sanitize_provider_error_pages(&m(&[("503", "file:///etc/passwd")]));
        assert!(out.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("file://"));
        assert!(warnings[0].contains("503"));
    }

    #[test]
    fn provider_unsupported_code_is_dropped() {
        let (out, warnings) = sanitize_provider_error_pages(&m(&[("200", "OK")]));
        assert!(out.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("200"));
        assert!(warnings[0].contains("not supported"));
    }

    #[test]
    fn wrap_multiline_body_content_length_counts_crlf() {
        // Sōzu normalizes LF -> CRLF before serving; Content-Length must count
        // the CRLF form or the tail is truncated on the wire. A 3-line body
        // (two LF) carries +2 bytes once normalized.
        let body = "a\nb\nc"; // 5 bytes as LF, 7 bytes as CRLF
        let wrapped = wrap_body_into_http_response("404", body);
        assert!(wrapped.contains("Content-Length: 7\r\n"));
        assert!(wrapped.ends_with("a\r\nb\r\nc"));
    }

    #[test]
    fn wrap_plain_body_produces_valid_http_response() {
        let wrapped = wrap_body_into_http_response("503", "<h1>Down</h1>");
        assert!(wrapped.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(wrapped.contains("Content-Length: 13\r\n"));
        assert!(wrapped.contains("Content-Type: text/html"));
        assert!(wrapped.contains("Connection: close"));
        assert!(wrapped.ends_with("<h1>Down</h1>"));
        assert!(wrapped.contains("\r\n\r\n<h1>Down</h1>"));
    }

    #[test]
    fn wrap_http_value_passes_through_unchanged() {
        let raw = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(wrap_body_into_http_response("404", raw), raw);
    }

    #[test]
    fn wrap_file_uri_reads_and_wraps_plain_html() {
        // A file:// template authored as plain HTML must be read and wrapped
        // into a full HTTP/1.1 response (Sōzu does not wrap file contents).
        let dir = std::env::temp_dir();
        let path = dir.join("sozune_test_404_plain.html");
        std::fs::write(&path, "<h1>Gone</h1>").unwrap();
        let value = format!("file://{}", path.display());

        let wrapped = wrap_body_into_http_response("404", &value);
        assert!(wrapped.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(wrapped.contains("Content-Length: 13\r\n"));
        assert!(wrapped.ends_with("<h1>Gone</h1>"));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrap_file_uri_passes_through_full_http_response() {
        // A file:// template that already is a full HTTP response is served
        // verbatim, no double-wrapping.
        let dir = std::env::temp_dir();
        let path = dir.join("sozune_test_404_full.http");
        let raw = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        std::fs::write(&path, raw).unwrap();
        let value = format!("file://{}", path.display());

        assert_eq!(wrap_body_into_http_response("404", &value), raw);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrap_file_uri_missing_path_falls_back_to_literal() {
        // An unreadable path does not panic: the literal value is wrapped so
        // the misconfiguration is visible rather than fatal.
        let wrapped = wrap_body_into_http_response("404", "file:///nonexistent/sozune/never.html");
        assert!(wrapped.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(wrapped.ends_with("file:///nonexistent/sozune/never.html"));
    }

    #[test]
    fn wrap_unknown_code_uses_custom_reason() {
        let wrapped = wrap_body_into_http_response("418", "teapot");
        assert!(wrapped.starts_with("HTTP/1.1 418 Custom\r\n"));
    }

    #[test]
    fn provider_mixed_input_keeps_only_safe_entries() {
        let (out, warnings) = sanitize_provider_error_pages(&m(&[
            ("404", "<p>missing</p>"),
            ("503", "file:///etc/shadow"),
            ("999", "junk"),
        ]));
        assert_eq!(out.len(), 1);
        assert!(out.contains_key("404"));
        assert_eq!(warnings.len(), 2);
    }
}
