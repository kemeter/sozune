//! Shared diagnostics store, populated by providers at parse time and read by
//! the API (`/entrypoints` and `/diagnostics` endpoints).
//!
//! Keyed by candidate id (the same id the candidate was parsed from), so that
//! callers can look up "what did the parser say about this container?". An
//! entrypoint id (cluster_id) may not match the candidate id 1:1 — a single
//! candidate can produce multiple entrypoints.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::labels::candidate::Candidate;
use crate::labels::diagnostic::{Diagnostic, ParseResult};

pub type DiagnosticsStore = Arc<RwLock<HashMap<String, Vec<Diagnostic>>>>;

pub fn new_store() -> DiagnosticsStore {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Replace the diagnostics for a single candidate.
///
/// Empty `diags` removes the entry rather than storing an empty vec — callers
/// reading the map can then assume "key present" ⟺ "has at least one diag".
pub fn set(store: &DiagnosticsStore, candidate_id: &str, diags: Vec<Diagnostic>) {
    let mut guard = match store.write() {
        Ok(g) => g,
        Err(e) => {
            tracing::error!(
                "internal state corrupted (diagnostics store), restart required: {}",
                e
            );
            return;
        }
    };
    if diags.is_empty() {
        guard.remove(candidate_id);
    } else {
        guard.insert(candidate_id.to_string(), diags);
    }
}

/// Drop the diagnostics for a candidate that no longer exists.
pub fn remove(store: &DiagnosticsStore, candidate_id: &str) {
    let mut guard = match store.write() {
        Ok(g) => g,
        Err(e) => {
            tracing::error!(
                "internal state corrupted (diagnostics store), restart required: {}",
                e
            );
            return;
        }
    };
    guard.remove(candidate_id);
}

/// Parse a candidate and write the resulting diagnostics into the store keyed
/// by `candidate.id`. Returns the parse result so callers can use the
/// entrypoints. Empty diagnostics remove any existing entry.
///
/// Use this in providers as a drop-in replacement for `labels::parse(&c)`
/// when you want diagnostics to surface in the API.
pub fn parse_and_store(store: &DiagnosticsStore, candidate: &Candidate) -> ParseResult {
    let result = crate::labels::parse(candidate);
    set(store, &candidate.id, result.diagnostics.clone());
    result
}

/// Snapshot of all current diagnostics. Returns a flat list with the candidate
/// id attached to each diagnostic for cross-referencing.
pub fn snapshot(store: &DiagnosticsStore) -> Vec<(String, Vec<Diagnostic>)> {
    match store.read() {
        Ok(g) => g.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        Err(e) => {
            tracing::error!(
                "internal state corrupted (diagnostics store), restart required: {}",
                e
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels::diagnostic::DiagnosticCode;

    fn diag() -> Diagnostic {
        Diagnostic::new(DiagnosticCode::W001InvalidPort, "test")
    }

    #[test]
    fn set_then_snapshot_returns_inserted() {
        let s = new_store();
        set(&s, "c1", vec![diag()]);
        let snap = snapshot(&s);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, "c1");
        assert_eq!(snap[0].1.len(), 1);
    }

    #[test]
    fn set_with_empty_removes_entry() {
        let s = new_store();
        set(&s, "c1", vec![diag()]);
        set(&s, "c1", vec![]);
        assert!(snapshot(&s).is_empty());
    }

    #[test]
    fn remove_drops_entry() {
        let s = new_store();
        set(&s, "c1", vec![diag()]);
        remove(&s, "c1");
        assert!(snapshot(&s).is_empty());
    }
}
