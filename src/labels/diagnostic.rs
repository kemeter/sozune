use crate::model::Entrypoint;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub code: DiagnosticCode,
    pub label: Option<String>,
    pub value: Option<String>,
    pub message: String,
    pub hint: Option<String>,
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
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity() == Severity::Error)
    }
}
