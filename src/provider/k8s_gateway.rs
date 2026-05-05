//! Kubernetes Gateway API watcher (scaffold).
//!
//! This is the first step toward Gateway API support: we watch HTTPRoute
//! resources cluster-wide and log what we observe. No conversion to Sozune
//! entrypoints yet — that comes once the watcher is proven stable on a real
//! cluster.
//!
//! Pairing with [`KubernetesProvider`](super::kubernetes::KubernetesProvider):
//! the existing provider keeps owning Service/Ingress/EndpointSlice. This
//! module owns Gateway API CRDs (HTTPRoute now, Gateway/GatewayClass next).
//! The two run side by side and feed the same shared storage through
//! reload signals.
//!
//! References: <https://gateway-api.sigs.k8s.io/api-types/httproute/>

use anyhow::Context;
use futures_util::StreamExt;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use tracing::{debug, error, info, warn};

/// Kick off a HTTPRoute watch on the given client. Runs forever (until the
/// kube watcher errors permanently). On transient errors the watcher
/// internally backs off and resumes.
pub async fn run_httproute_watcher(client: Client) -> anyhow::Result<()> {
    let api: Api<HTTPRoute> = Api::all(client);
    let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();

    info!("Gateway API: HTTPRoute watcher started");

    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Apply(route)) => log_route("apply", &route),
            Ok(Event::Delete(route)) => log_route("delete", &route),
            Ok(Event::Init) => debug!("Gateway API: HTTPRoute init"),
            Ok(Event::InitApply(route)) => log_route("init-apply", &route),
            Ok(Event::InitDone) => debug!("Gateway API: HTTPRoute init done"),
            Err(e) => {
                error!("Gateway API: HTTPRoute watcher error: {}", e);
            }
        }
    }

    warn!("Gateway API: HTTPRoute watcher stream ended unexpectedly");
    Ok(())
}

/// Validate that the cluster knows about the Gateway API CRDs before we
/// start the watcher. Returns Ok(true) if the CRD is installed, Ok(false)
/// otherwise. Anything else (network error, RBAC denial) bubbles up so the
/// caller can decide whether to keep retrying.
pub async fn httproute_crd_installed(client: &Client) -> anyhow::Result<bool> {
    let api: Api<HTTPRoute> = Api::all(client.clone());
    match api.list(&Default::default()).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(err)) if err.code == 404 => Ok(false),
        Err(e) => Err(e).context("probing for Gateway API HTTPRoute CRD"),
    }
}

fn log_route(action: &str, route: &HTTPRoute) {
    let ns = route
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("<no-namespace>");
    let name = route.metadata.name.as_deref().unwrap_or("<no-name>");
    let hosts = route
        .spec
        .hostnames
        .as_ref()
        .map(|v| v.join(","))
        .unwrap_or_default();
    let rules = route.spec.rules.as_ref().map(|v| v.len()).unwrap_or(0);
    info!(
        "Gateway API: HTTPRoute {} {}/{} hosts=[{}] rules={}",
        action, ns, name, hosts, rules
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check that the gateway-api crate types compile and that the
    /// fields we read in `log_route` actually exist with the shapes we
    /// assume (Option<Vec<String>> for hostnames, Option<Vec<rule>> for
    /// rules). If gateway-api ever bumps and changes these shapes, this
    /// test fails at compile time.
    #[test]
    fn httproute_shape_matches_what_we_read() {
        let r = HTTPRoute::default();
        let _: Option<Vec<String>> = r.spec.hostnames;
        let _: Option<Vec<gateway_api::apis::standard::httproutes::HTTPRouteRules>> = r.spec.rules;
    }
}
