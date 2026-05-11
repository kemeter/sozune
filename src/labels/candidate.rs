use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Candidate {
    pub provider: &'static str,
    pub id: String,
    pub display_name: String,
    pub labels: HashMap<String, String>,
    pub networks: Vec<NetworkInfo>,
    pub enabled_default: bool,
    /// Docker `HEALTHCHECK` state when one is declared on the container.
    /// `None` means no healthcheck declared (or provider doesn't expose health
    /// signals) — caller treats this as "no gating".
    pub health: Option<HealthStatus>,
}

#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub name: String,
    pub ip: Option<String>,
}

/// Container-level health signal reported by an orchestrator. Mirrors the
/// Docker `State.Health.Status` field — providers that don't surface a
/// healthcheck leave `Candidate.health` as `None` instead of using a variant
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Starting,
    Healthy,
    Unhealthy,
}

impl HealthStatus {
    /// Whether the container should receive traffic given this health state.
    /// `Healthy` routes; `Starting` and `Unhealthy` don't.
    pub fn is_routable(self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_healthy_routes() {
        assert!(HealthStatus::Healthy.is_routable());
        assert!(!HealthStatus::Starting.is_routable());
        assert!(!HealthStatus::Unhealthy.is_routable());
    }
}
