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

impl Candidate {
    /// The workload this candidate is a replica of, which a `serviceWeight`
    /// is shared by: for a container, its Compose service (Docker and
    /// Podman Compose label their containers with it) or the Swarm service
    /// of its task, else the container itself; for the other providers,
    /// the service or deployment it is an instance of.
    pub fn workload(&self) -> String {
        let label = |name: &str| self.labels.get(name).filter(|v| !v.is_empty());
        if let (Some(project), Some(service)) = (
            label("com.docker.compose.project"),
            label("com.docker.compose.service"),
        ) {
            return format!("{project}/{service}");
        }
        if let Some(service) = label("com.docker.swarm.service.name") {
            return service.clone();
        }
        if matches!(
            self.provider,
            crate::provider::DOCKER | crate::provider::PODMAN
        ) {
            return self.id.clone();
        }
        self.display_name.clone()
    }
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

    fn candidate(provider: &'static str, labels: &[(&str, &str)]) -> Candidate {
        Candidate {
            provider,
            id: "c0ffee".into(),
            display_name: "web-1".into(),
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            networks: Vec::new(),
            enabled_default: false,
            health: None,
        }
    }

    #[test]
    fn a_container_is_a_replica_of_its_compose_or_swarm_service() {
        let compose = candidate(
            crate::provider::DOCKER,
            &[
                ("com.docker.compose.project", "shop"),
                ("com.docker.compose.service", "api"),
            ],
        );
        assert_eq!(compose.workload(), "shop/api");
        let task = candidate(
            crate::provider::DOCKER,
            &[("com.docker.swarm.service.name", "shop_api")],
        );
        assert_eq!(task.workload(), "shop_api");
        // A container of no service is its own.
        assert_eq!(candidate(crate::provider::PODMAN, &[]).workload(), "c0ffee");
    }

    #[test]
    fn an_instance_is_a_replica_of_its_service() {
        assert_eq!(candidate(crate::provider::NOMAD, &[]).workload(), "web-1");
        assert_eq!(candidate(crate::provider::RING, &[]).workload(), "web-1");
    }
}
