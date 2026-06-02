use crate::labels::Candidate;
use crate::model::Entrypoint;
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use tracing::{debug, error, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warn,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticCode {
    // Errors — block routing
    E001Disabled,
    E002MissingHost,
    /// Reserved: documented in `sozune explain E003` but not yet emitted at
    /// runtime. Belongs to the Docker provider when `inspect_container`
    /// fails — surface that path before removing the variant.
    #[allow(dead_code)]
    E003InspectFailed,
    E004NoServices,
    E005MissingTcpEntrypoint,
    // Warnings — silent fallbacks today
    W001InvalidPort,
    W002InvalidPriority,
    W003InvalidTimeout,
    W004InvalidRateLimit,
    W005InvalidRedirectPolicy,
    W006InvalidRedirectScheme,
    W007MalformedBasicAuthEntry,
    W008BlockedHeader,
    W009NetworkNotFound,
    W010NoIpFellBackToLocalhost,
    W011EmptyBasicAuth,
    W012InvalidProtocol,
    W013UnknownLabel,
    W014InvalidMethod,
    W015AcmeWithoutTls,
    W016HttpsRedirectWithoutTls,
    W017RateLimitBurstBelowAverage,
    W018RouteCollision,
    W019InvalidForwardAuth,
    W020InvalidErrorPage,
    W021InvalidHealthCheck,
    W022InvalidLoadBalancer,
    W023InvalidRetry,
    // Info — surfaced only with --severity info
    I001PathDefaulted,
    I002PortDefaulted,
}

impl DiagnosticCode {
    pub fn as_str(self) -> &'static str {
        match self {
            DiagnosticCode::E001Disabled => "E001",
            DiagnosticCode::E002MissingHost => "E002",
            DiagnosticCode::E003InspectFailed => "E003",
            DiagnosticCode::E004NoServices => "E004",
            DiagnosticCode::E005MissingTcpEntrypoint => "E005",
            DiagnosticCode::W001InvalidPort => "W001",
            DiagnosticCode::W002InvalidPriority => "W002",
            DiagnosticCode::W003InvalidTimeout => "W003",
            DiagnosticCode::W004InvalidRateLimit => "W004",
            DiagnosticCode::W005InvalidRedirectPolicy => "W005",
            DiagnosticCode::W006InvalidRedirectScheme => "W006",
            DiagnosticCode::W007MalformedBasicAuthEntry => "W007",
            DiagnosticCode::W008BlockedHeader => "W008",
            DiagnosticCode::W009NetworkNotFound => "W009",
            DiagnosticCode::W010NoIpFellBackToLocalhost => "W010",
            DiagnosticCode::W011EmptyBasicAuth => "W011",
            DiagnosticCode::W012InvalidProtocol => "W012",
            DiagnosticCode::W013UnknownLabel => "W013",
            DiagnosticCode::W014InvalidMethod => "W014",
            DiagnosticCode::W015AcmeWithoutTls => "W015",
            DiagnosticCode::W016HttpsRedirectWithoutTls => "W016",
            DiagnosticCode::W017RateLimitBurstBelowAverage => "W017",
            DiagnosticCode::W018RouteCollision => "W018",
            DiagnosticCode::W019InvalidForwardAuth => "W019",
            DiagnosticCode::W020InvalidErrorPage => "W020",
            DiagnosticCode::W021InvalidHealthCheck => "W021",
            DiagnosticCode::W022InvalidLoadBalancer => "W022",
            DiagnosticCode::W023InvalidRetry => "W023",
            DiagnosticCode::I001PathDefaulted => "I001",
            DiagnosticCode::I002PortDefaulted => "I002",
        }
    }

    pub fn severity(self) -> Severity {
        match self.as_str().chars().next() {
            Some('E') => Severity::Error,
            Some('W') => Severity::Warn,
            _ => Severity::Info,
        }
    }
}

impl Serialize for DiagnosticCode {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub label: Option<String>,
    pub value: Option<String>,
    pub message: String,
    pub hint: Option<String>,
}

impl Serialize for Diagnostic {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut len = 3; // code, severity, message
        if self.label.is_some() {
            len += 1;
        }
        if self.value.is_some() {
            len += 1;
        }
        if self.hint.is_some() {
            len += 1;
        }
        let mut m = s.serialize_map(Some(len))?;
        m.serialize_entry("code", self.code.as_str())?;
        m.serialize_entry("severity", &self.severity())?;
        m.serialize_entry("message", &self.message)?;
        if let Some(label) = &self.label {
            m.serialize_entry("label", label)?;
        }
        if let Some(value) = &self.value {
            m.serialize_entry("value", value)?;
        }
        if let Some(hint) = &self.hint {
            m.serialize_entry("hint", hint)?;
        }
        m.end()
    }
}

impl Diagnostic {
    pub fn new(code: DiagnosticCode, message: impl Into<String>) -> Self {
        Self {
            code,
            label: None,
            value: None,
            message: message.into(),
            hint: None,
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn severity(&self) -> Severity {
        self.code.severity()
    }
}

#[derive(Debug, Default)]
pub struct ParseResult {
    pub entrypoints: HashMap<String, Entrypoint>,
    pub diagnostics: Vec<Diagnostic>,
}

impl ParseResult {
    /// Whether any diagnostic in this result is `Severity::Error`.
    /// Exercised by the parser tests; kept as part of the public API surface
    /// so test fixtures and external consumers can gate on parse errors
    /// without re-implementing the filter.
    #[allow(dead_code)]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity() == Severity::Error)
    }
}

/// Emit each diagnostic at the appropriate tracing level so the runtime logs
/// match what `sozune validate` would report. Shared by every provider that
/// turns a `Candidate` into entrypoints — see `provider::{docker,swarm,nomad,kubernetes}`.
pub(crate) fn log_diagnostics(candidate: &Candidate, diagnostics: &[Diagnostic]) {
    for d in diagnostics {
        let target = format!("{}/{}", candidate.provider, candidate.display_name);
        match d.severity() {
            Severity::Error => error!(
                "[{}] {}: {} (label={})",
                target,
                d.code.as_str(),
                d.message,
                d.label.as_deref().unwrap_or("-")
            ),
            Severity::Warn => warn!(
                "[{}] {}: {} (label={}, value={:?})",
                target,
                d.code.as_str(),
                d.message,
                d.label.as_deref().unwrap_or("-"),
                d.value.as_deref().unwrap_or("")
            ),
            Severity::Info => debug!("[{}] {}: {}", target, d.code.as_str(), d.message),
        }
    }
}
