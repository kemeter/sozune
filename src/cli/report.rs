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
        let has_error = diagnostics.iter().any(|d| d.severity() == Severity::Error);
        let has_warn = diagnostics.iter().any(|d| d.severity() == Severity::Warn);

        let status = if entrypoints.is_empty() || has_error {
            Status::Skipped
        } else if has_warn {
            Status::Degraded
        } else {
            Status::Routed
        };

        Self {
            provider: candidate.provider.to_string(),
            id: candidate.id.clone(),
            display_name: candidate.display_name.clone(),
            status,
            entrypoints,
            diagnostics,
        }
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
