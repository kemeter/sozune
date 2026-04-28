use crate::cli::report::{CandidateReport, Status, ValidationReport};
use crate::labels::diagnostic::{Diagnostic, Severity};
use crate::model::{Entrypoint, PathConfig, PathRuleType, Protocol};
use std::fmt::Write;

pub fn render(report: &ValidationReport, min_severity: Severity) -> String {
    let mut out = String::new();
    let mut by_provider: std::collections::BTreeMap<&str, Vec<&CandidateReport>> =
        std::collections::BTreeMap::new();
    for c in &report.candidates {
        by_provider.entry(c.provider.as_str()).or_default().push(c);
    }

    for (provider, mut candidates) in by_provider {
        candidates.sort_by(|a, b| a.display_name.cmp(&b.display_name));
        writeln!(&mut out, "{provider}").unwrap();

        let last_idx = candidates.len().saturating_sub(1);
        for (i, candidate) in candidates.iter().enumerate() {
            let is_last = i == last_idx;
            render_candidate(&mut out, candidate, is_last, min_severity);
            if !is_last {
                writeln!(&mut out, "│").unwrap();
            }
        }
        writeln!(&mut out).unwrap();
    }

    let s = report.summary();
    writeln!(
        &mut out,
        "{} routed · {} degraded · {} skipped",
        s.routed, s.degraded, s.skipped
    )
    .unwrap();
    if has_diagnostics(report, min_severity) {
        writeln!(
            &mut out,
            "Run `sozune validate --explain <CODE>` for details on a diagnostic code."
        )
        .unwrap();
    }
    out
}

fn render_candidate(
    out: &mut String,
    candidate: &CandidateReport,
    is_last: bool,
    min_severity: Severity,
) {
    let branch = if is_last { "└─" } else { "├─" };
    let cont = if is_last { "  " } else { "│ " };

    let glyph = match candidate.status {
        Status::Routed => "✓",
        Status::Degraded => "⚠",
        Status::Skipped => "✗",
    };
    let suffix = match candidate.status {
        Status::Routed => String::new(),
        Status::Degraded => "  ·  degraded".into(),
        Status::Skipped => "  ·  skipped".into(),
    };

    let short_id = if candidate.id.len() > 12 {
        format!(" ({})", &candidate.id[..12])
    } else if candidate.id.is_empty() || candidate.id == candidate.display_name {
        String::new()
    } else {
        format!(" ({})", candidate.id)
    };

    writeln!(
        out,
        "{branch} {glyph} {name}{id}{suffix}",
        name = candidate.display_name,
        id = short_id,
    )
    .unwrap();

    // Routing summary line per entrypoint.
    let mut sorted_eps: Vec<&Entrypoint> = candidate.entrypoints.values().collect();
    sorted_eps.sort_by(|a, b| a.id.cmp(&b.id));
    for ep in &sorted_eps {
        writeln!(out, "{cont}     {}", format_route(ep)).unwrap();
    }

    // Diagnostics, filtered by min_severity.
    let visible: Vec<&Diagnostic> = candidate
        .diagnostics
        .iter()
        .filter(|d| severity_at_least(d.severity(), min_severity))
        .collect();

    if visible.is_empty() {
        return;
    }

    writeln!(out, "{cont}    │").unwrap();
    let last_diag = visible.len().saturating_sub(1);
    for (i, diag) in visible.iter().enumerate() {
        let dlast = i == last_diag;
        let dbranch = if dlast { "└─" } else { "├─" };
        let dcont = if dlast { "   " } else { "│  " };
        let header = format_diag_header(diag);
        writeln!(out, "{cont}    {dbranch} {} {header}", diag.code.as_str()).unwrap();
        writeln!(out, "{cont}    {dcont}      {}", diag.message).unwrap();
        if let Some(hint) = &diag.hint {
            writeln!(out, "{cont}    {dcont}      → {hint}").unwrap();
        }
        if !dlast {
            writeln!(out, "{cont}    │").unwrap();
        }
    }
}

fn format_route(ep: &Entrypoint) -> String {
    let scheme = match ep.protocol {
        Protocol::Http => {
            if ep.config.tls {
                "https"
            } else {
                "http"
            }
        }
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };
    let host = ep.config.hostnames.first().cloned().unwrap_or_default();
    let path_str = ep
        .config
        .path
        .as_ref()
        .map(format_path)
        .unwrap_or_default();
    let backends = ep.backends.join(", ");
    format!(
        "{}://{}:{}{}  →  {}",
        scheme, host, ep.config.port, path_str, backends
    )
}

fn format_path(p: &PathConfig) -> String {
    match p.rule_type {
        PathRuleType::Prefix | PathRuleType::Exact => p.value.clone(),
        PathRuleType::Regex => format!(" (regex: {})", p.value),
    }
}

fn format_diag_header(diag: &Diagnostic) -> String {
    match (&diag.label, &diag.value) {
        (Some(label), Some(value)) => format!("{label} = {value:?}"),
        (Some(label), None) => label.clone(),
        (None, Some(value)) => format!("{value:?}"),
        (None, None) => String::new(),
    }
}

fn severity_at_least(d: Severity, min: Severity) -> bool {
    severity_rank(d) >= severity_rank(min)
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warn => 1,
        Severity::Error => 2,
    }
}

fn has_diagnostics(report: &ValidationReport, min: Severity) -> bool {
    report
        .candidates
        .iter()
        .flat_map(|c| c.diagnostics.iter())
        .any(|d| severity_at_least(d.severity(), min))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::report::CandidateReport;
    use crate::labels::candidate::Candidate;
    use crate::labels::diagnostic::DiagnosticCode;
    use crate::labels::parse;
    use std::collections::HashMap;

    fn candidate(provider: &'static str, name: &str, labels: &[(&str, &str)]) -> Candidate {
        Candidate {
            provider,
            id: format!("{name}-id"),
            display_name: name.into(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            networks: vec![crate::labels::candidate::NetworkInfo {
                name: "bridge".into(),
                ip: Some("172.18.0.4".into()),
            }],
            enabled_default: false,
        }
    }

    fn report_for(c: Candidate) -> CandidateReport {
        let r = parse(&c);
        CandidateReport::from_parse(&c, r.entrypoints, r.diagnostics)
    }

    #[test]
    fn routed_candidate_renders_route_line() {
        let c = candidate(
            "docker",
            "my-api",
            &[
                ("sozune.enable", "true"),
                ("sozune.http.web.host", "example.com"),
                ("sozune.http.web.port", "8080"),
            ],
        );
        let report = ValidationReport {
            candidates: vec![report_for(c)],
        };
        let out = render(&report, Severity::Warn);
        assert!(out.contains("docker"));
        assert!(out.contains("✓ my-api"));
        assert!(out.contains("http://example.com:8080"));
        assert!(out.contains("172.18.0.4"));
        assert!(out.contains("1 routed · 0 degraded · 0 skipped"));
    }

    #[test]
    fn skipped_candidate_shows_e002_with_hint() {
        let c = candidate(
            "docker",
            "broken",
            &[
                ("sozune.enable", "true"),
                ("sozune.http.web.port", "8080"),
            ],
        );
        let report = ValidationReport {
            candidates: vec![report_for(c)],
        };
        let out = render(&report, Severity::Warn);
        assert!(out.contains("✗ broken"));
        assert!(out.contains("skipped"));
        assert!(out.contains("E002"));
        assert!(out.contains("→"));
    }

    #[test]
    fn degraded_candidate_emits_warn_glyph() {
        let c = candidate(
            "docker",
            "weird",
            &[
                ("sozune.enable", "true"),
                ("sozune.http.web.host", "example.com"),
                ("sozune.http.web.port", "abc"),
            ],
        );
        let report = ValidationReport {
            candidates: vec![report_for(c)],
        };
        let out = render(&report, Severity::Warn);
        assert!(out.contains("⚠ weird"));
        assert!(out.contains("degraded"));
        assert!(out.contains("W001"));
    }

    #[test]
    fn min_severity_filters_diagnostics() {
        let c = candidate(
            "docker",
            "api",
            &[
                ("sozune.enable", "true"),
                ("sozune.http.web.host", "example.com"),
            ],
        );
        let report = ValidationReport {
            candidates: vec![report_for(c)],
        };
        // I-codes are emitted (path defaulted, port defaulted), but Warn
        // filter should hide them.
        let warn = render(&report, Severity::Warn);
        assert!(!warn.contains("I001"));
        assert!(!warn.contains("I002"));

        let info = render(&report, Severity::Info);
        assert!(info.contains("I001") || info.contains("I002"));
    }

    #[test]
    fn groups_by_provider() {
        let c1 = candidate(
            "docker",
            "a",
            &[("sozune.enable", "true"), ("sozune.http.x.host", "a.io")],
        );
        let c2 = candidate(
            "file",
            "b",
            &[("sozune.enable", "true"), ("sozune.http.x.host", "b.io")],
        );
        let report = ValidationReport {
            candidates: vec![report_for(c1), report_for(c2)],
        };
        let out = render(&report, Severity::Warn);
        let docker_pos = out.find("docker").unwrap();
        let file_pos = out.find("file").unwrap();
        assert!(docker_pos < file_pos);
        // Make sure unused import warning doesn't fire and the helper
        // produces a non-empty diagnostic header for completeness.
        let _ = DiagnosticCode::E002MissingHost.as_str();
        let _: HashMap<String, Entrypoint> = HashMap::new();
    }
}
