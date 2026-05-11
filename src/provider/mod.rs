use crate::model::Entrypoint;
use async_trait::async_trait;
use std::collections::BTreeMap;

/// Canonical provider identifiers. Each provider's `Provider::name()`
/// returns one of these, every `Entrypoint::source` set by a provider
/// uses one of these, and the `/providers` API endpoint iterates over
/// `ALL` to render its rows. Single source of truth so the three never
/// drift apart.
pub const DOCKER: &str = "docker";
pub const PODMAN: &str = "podman";
pub const SWARM: &str = "swarm";
pub const KUBERNETES: &str = "kubernetes";
pub const NOMAD: &str = "nomad";
pub const HTTP: &str = "http";
pub const CONFIG: &str = "config";

/// Every provider known to sōzune, in display order for `/providers`.
pub const ALL: &[&str] = &[DOCKER, PODMAN, SWARM, KUBERNETES, NOMAD, HTTP, CONFIG];

#[async_trait]
pub trait Provider {
    async fn provide(&self) -> anyhow::Result<BTreeMap<String, Entrypoint>>;
}

pub mod config;
pub mod docker;
pub mod factory;
pub mod http;
pub mod kubernetes;
pub mod nomad;
pub mod podman;
pub mod swarm;
