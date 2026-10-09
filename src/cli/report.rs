use crate::labels::candidate::Candidate;
use crate::labels::diagnostic::{Diagnostic, Severity};
use crate::model::Entrypoint;
use std::collections::HashMap;

/// Final, render-ready view of validating one candidate.
pub struct CandidateReport {
    pub provider: String,
    pub id: String,
    pub display_name: String,
    pub status: Status,
    pub entrypoints: HashMap<String, Entrypoint>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Routed,
    Degraded,
    Skipped,
}

impl CandidateReport {
    pub fn from_parse(
        candidate: &Candidate,
        entrypoints: HashMap<String, Entrypoint>,
        diagnostics: Vec<Diagnostic>,
    ) -> Self {
        let status = status_of(&entrypoints, &diagnostics);

        Self {
            provider: candidate.provider.to_string(),
            id: candidate.id.clone(),
            display_name: candidate.display_name.clone(),
            status,
            entrypoints,
            diagnostics,
        }
    }

    /// Attach a diagnostic found after parsing (a lint across candidates), and
    /// update the status it may degrade.
    pub fn push_diagnostic(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
        self.status = status_of(&self.entrypoints, &self.diagnostics);
    }
}

fn status_of(entrypoints: &HashMap<String, Entrypoint>, diagnostics: &[Diagnostic]) -> Status {
    let has_error = diagnostics.iter().any(|d| d.severity() == Severity::Error);
    let has_warn = diagnostics.iter().any(|d| d.severity() == Severity::Warn);

    if entrypoints.is_empty() || has_error {
        Status::Skipped
    } else if has_warn {
        Status::Degraded
    } else {
        Status::Routed
    }
}

pub struct ValidationReport {
    pub candidates: Vec<CandidateReport>,
}

impl ValidationReport {
    pub fn summary(&self) -> Summary {
        let mut s = Summary::default();
        for c in &self.candidates {
            match c.status {
                Status::Routed => s.routed += 1,
                Status::Degraded => s.degraded += 1,
                Status::Skipped => s.skipped += 1,
            }
        }
        s
    }
}

#[derive(Default)]
pub struct Summary {
    pub routed: usize,
    pub degraded: usize,
    pub skipped: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::diagnostic::DiagnosticCode;

    #[test]
    fn a_warning_pushed_after_parsing_degrades_a_routed_candidate() {
        let mut entrypoints = HashMap::new();
        entrypoints.insert(
            "http_app".to_string(),
            serde_json::from_value::<Entrypoint>(serde_json::json!({
                "id": "http_app",
                "name": "app",
                "backends": [{ "address": "10.0.0.1", "port": 80, "weight": 100 }],
                "protocol": "Http",
                "config": {
                    "hostnames": ["app.example.com"],
                    "path": null,
                    "tls": false,
                    "strip_prefix": false,
                    "https_redirect": false,
                    "priority": 0,
                    "auth": null,
                    "headers": []
                }
            }))
            .unwrap(),
        );
        let mut report = CandidateReport {
            provider: "docker".into(),
            id: "app".into(),
            display_name: "app".into(),
            status: status_of(&entrypoints, &[]),
            entrypoints,
            diagnostics: Vec::new(),
        };
        assert_eq!(report.status, Status::Routed);

        report.push_diagnostic(Diagnostic::new(
            DiagnosticCode::W029UnknownAcmeResolver,
            "unknown resolver",
        ));

        assert_eq!(report.status, Status::Degraded);
    }
}
