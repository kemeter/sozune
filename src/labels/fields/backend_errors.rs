use crate::labels::diagnostic::{Diagnostic, DiagnosticCode};
use crate::model::BackendErrorsConfig;
use std::collections::HashMap;

/// Parse the `<prefix>errors.*` labels: the error responses of the route
/// that a page replaces.
///
/// - `errors.status` — codes and ranges, comma-separated (`500-599,404`).
/// - `errors.page` — the page served instead, inline: `file://` is refused,
///   as for `errorPages`, so that a workload cannot serve host files.
/// - `errors.url` — where the page is fetched from, `{status}` and `{url}`
///   replaced; `errors.page` is served when the fetch fails.
///
/// Absent labels give `None` quietly. A missing or invalid status, or no page
/// to serve, emits `W032` and gives `None`.
pub fn parse_backend_errors(
    labels: &HashMap<String, String>,
    prefix: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<BackendErrorsConfig> {
    let status_key = format!("{prefix}errors.status");
    let page_key = format!("{prefix}errors.page");
    let url_key = format!("{prefix}errors.url");
    let value = |key: &str| {
        labels
            .get(key)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    let (status, mut page, url) = (value(&status_key), value(&page_key), value(&url_key));
    if status.is_none() && page.is_none() && url.is_none() {
        return None;
    }
    let warn = |message: String, key: &str, value: Option<&str>, hint: &str| {
        let mut diag = Diagnostic::new(DiagnosticCode::W034InvalidBackendErrors, message)
            .with_label(key)
            .with_hint(hint);
        if let Some(value) = value {
            diag = diag.with_value(value);
        }
        diag
    };

    if page.as_deref().is_some_and(|p| p.starts_with("file://")) {
        diagnostics.push(warn(
            "errors.page: file:// is refused for provider labels, dropped".to_string(),
            &page_key,
            page.as_deref(),
            "inline the page in the label value, or set it in static config under the entrypoint's `errors.page`",
        ));
        page = None;
    }

    let Some(status) = status else {
        diagnostics.push(warn(
            "errors.status is missing, the route's errors are not replaced".to_string(),
            &status_key,
            None,
            "list the statuses to replace, e.g. errors.status=500-599,404",
        ));
        return None;
    };
    let config = BackendErrorsConfig {
        status: vec![status],
        page,
        url,
    };
    if let Err(e) = config.status_ranges() {
        diagnostics.push(warn(
            format!("errors.status: {e}, the route's errors are not replaced"),
            &status_key,
            config.status.first().map(String::as_str),
            "use codes and ranges from 400 to 599, e.g. errors.status=500-599,404",
        ));
        return None;
    }
    if config.page.is_none() && config.url.is_none() {
        diagnostics.push(warn(
            "errors: neither errors.page nor errors.url is set, the route's errors are not replaced"
                .to_string(),
            &page_key,
            None,
            "set errors.page to an inline page, or errors.url to where the page is fetched from",
        ));
        return None;
    }
    Some(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "sozune.http.web.";

    fn parse(pairs: &[(&str, &str)]) -> (Option<BackendErrorsConfig>, Vec<Diagnostic>) {
        let labels = pairs
            .iter()
            .map(|(k, v)| (format!("{PREFIX}{k}"), (*v).to_string()))
            .collect();
        let mut diags = Vec::new();
        let config = parse_backend_errors(&labels, PREFIX, &mut diags);
        (config, diags)
    }

    #[test]
    fn absent_returns_none_quietly() {
        let (config, diags) = parse(&[]);
        assert!(config.is_none());
        assert!(diags.is_empty());
    }

    #[test]
    fn status_page_and_url_parse() {
        let (config, diags) = parse(&[
            ("errors.status", "500-599, 404"),
            ("errors.page", "<h1>down</h1>"),
            ("errors.url", "http://pages/{status}.html"),
        ]);
        assert!(diags.is_empty());
        let config = config.unwrap();
        assert_eq!(config.status_ranges().unwrap(), vec![500..=599, 404..=404]);
        assert_eq!(config.page.as_deref(), Some("<h1>down</h1>"));
        assert_eq!(config.url.as_deref(), Some("http://pages/{status}.html"));
    }

    #[test]
    fn missing_status_emits_w032() {
        let (config, diags) = parse(&[("errors.page", "down")]);
        assert!(config.is_none());
        assert_eq!(diags[0].code, DiagnosticCode::W034InvalidBackendErrors);
        assert_eq!(
            diags[0].label.as_deref(),
            Some("sozune.http.web.errors.status")
        );
    }

    #[test]
    fn invalid_status_emits_w032() {
        let (config, diags) = parse(&[("errors.status", "200-299"), ("errors.page", "down")]);
        assert!(config.is_none());
        assert_eq!(diags[0].code, DiagnosticCode::W034InvalidBackendErrors);
    }

    #[test]
    fn nothing_to_serve_emits_w032() {
        let (config, diags) = parse(&[("errors.status", "500-599")]);
        assert!(config.is_none());
        assert_eq!(diags[0].code, DiagnosticCode::W034InvalidBackendErrors);
    }

    #[test]
    fn a_file_page_is_refused_but_the_url_kept() {
        let (config, diags) = parse(&[
            ("errors.status", "502"),
            ("errors.page", "file:///etc/passwd"),
            ("errors.url", "http://pages/502.html"),
        ]);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, DiagnosticCode::W034InvalidBackendErrors);
        let config = config.unwrap();
        assert!(config.page.is_none());
        assert_eq!(config.url.as_deref(), Some("http://pages/502.html"));
    }
}
