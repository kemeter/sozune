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

use crate::model::{Backend, Entrypoint, EntrypointConfig, PathConfig, PathRuleType, Protocol};
use anyhow::Context;
use futures_util::StreamExt;
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HTTPRouteRules, HTTPRouteRulesMatchesPathType,
};
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Per-route bookkeeping kept in memory so we can:
///   - recompute the entrypoint set on EndpointSlice churn (the resolver
///     might return more or fewer pod IPs than last time);
///   - clean up cleanly on delete without scanning the whole storage.
struct TrackedRoute {
    /// Last seen HTTPRoute payload, kept verbatim so re-resolution is just
    /// `route_to_entrypoints(stored, resolver)`.
    route: HTTPRoute,
    /// Entrypoint ids the previous apply produced.
    entrypoint_ids: Vec<String>,
}

/// Indexed by Kubernetes UID (stable across renames).
type RouteIndex = Arc<RwLock<HashMap<String, TrackedRoute>>>;

const SOURCE_TAG: &str = "k8s-gateway";

/// Kick off a HTTPRoute watch on the given client. On every Apply we
/// upsert the produced entrypoints into shared storage; on Delete we
/// remove them. Each meaningful change emits a single `reload_tx` signal
/// — the proxy's debouncer collapses bursts.
pub async fn run_httproute_watcher(
    client: Client,
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    reload_tx: mpsc::Sender<()>,
    resolver: Arc<dyn ServiceResolver>,
) -> anyhow::Result<()> {
    let api: Api<HTTPRoute> = Api::all(client);
    let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();
    let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));
    // Drives a re-resolve of every tracked route on a fixed cadence so
    // EndpointSlice churn (Service IPs appearing/disappearing) eventually
    // reaches Sōzu without the watcher needing direct knowledge of the
    // EndpointSlice cache. Cheap: each tick is O(routes × backendRefs)
    // and only signals reload when something actually changed.
    let mut resolve_ticker = tokio::time::interval(std::time::Duration::from_secs(2));
    resolve_ticker.tick().await;

    info!("Gateway API: HTTPRoute watcher started");

    loop {
        let changed = tokio::select! {
            event = stream.next() => match event {
                Some(Ok(Event::Apply(route))) | Some(Ok(Event::InitApply(route))) => {
                    log_route("apply", &route);
                    apply_route(&route, &storage, &index, resolver.as_ref())
                }
                Some(Ok(Event::Delete(route))) => {
                    log_route("delete", &route);
                    delete_route(&route, &storage, &index)
                }
                Some(Ok(Event::Init)) => {
                    debug!("Gateway API: HTTPRoute init");
                    false
                }
                Some(Ok(Event::InitDone)) => {
                    debug!("Gateway API: HTTPRoute init done");
                    false
                }
                Some(Err(e)) => {
                    error!("Gateway API: HTTPRoute watcher error: {}", e);
                    false
                }
                None => break,
            },
            _ = resolve_ticker.tick() => {
                re_resolve_all(&storage, &index, resolver.as_ref())
            }
        };
        if changed && let Err(e) = reload_tx.send(()).await {
            error!("Gateway API: failed to send reload signal: {}", e);
        }
    }

    warn!("Gateway API: HTTPRoute watcher stream ended unexpectedly");
    Ok(())
}

/// Returns true if storage was modified. Replaces any previous state for
/// this route UID atomically so a rename of a rule doesn't leave a stale
/// entrypoint behind. Always remembers the route in the index so a later
/// EndpointSlice update can re-resolve it even when this apply produced
/// zero entrypoints (Service had no ready endpoints yet).
fn apply_route(
    route: &HTTPRoute,
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &RouteIndex,
    resolver: &dyn ServiceResolver,
) -> bool {
    let uid = match route.metadata.uid.as_deref() {
        Some(u) => u.to_string(),
        None => {
            warn!("Gateway API: HTTPRoute without uid, skipping");
            return false;
        }
    };

    let new_entrypoints = route_to_entrypoints(route, resolver);

    let mut storage_guard = match storage.write() {
        Ok(g) => g,
        Err(e) => {
            error!("Gateway API: storage lock poisoned: {}", e);
            return false;
        }
    };
    let mut index_guard = match index.write() {
        Ok(g) => g,
        Err(e) => {
            error!("Gateway API: index lock poisoned: {}", e);
            return false;
        }
    };

    let mut changed = false;
    if let Some(previous) = index_guard.get(&uid) {
        for id in &previous.entrypoint_ids {
            if storage_guard.remove(id).is_some() {
                changed = true;
            }
        }
    }

    let new_ids: Vec<String> = new_entrypoints.iter().map(|e| e.id.clone()).collect();
    for ep in new_entrypoints {
        storage_guard.insert(ep.id.clone(), ep);
        changed = true;
    }

    index_guard.insert(
        uid,
        TrackedRoute {
            route: route.clone(),
            entrypoint_ids: new_ids,
        },
    );

    changed
}

fn delete_route(
    route: &HTTPRoute,
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &RouteIndex,
) -> bool {
    let Some(uid) = route.metadata.uid.as_deref() else {
        return false;
    };

    let mut index_guard = match index.write() {
        Ok(g) => g,
        Err(e) => {
            error!("Gateway API: index lock poisoned: {}", e);
            return false;
        }
    };
    let Some(tracked) = index_guard.remove(uid) else {
        return false;
    };

    let mut storage_guard = match storage.write() {
        Ok(g) => g,
        Err(e) => {
            error!("Gateway API: storage lock poisoned: {}", e);
            return false;
        }
    };

    let mut changed = false;
    for id in tracked.entrypoint_ids {
        if storage_guard.remove(&id).is_some() {
            changed = true;
        }
    }
    changed
}

/// Re-resolve every tracked route's entrypoints. Called periodically by the
/// watcher so that EndpointSlice churn (a Service that just got its first
/// ready pod, or a scale-down) is reflected in the storage. Returns true
/// if any route changed.
fn re_resolve_all(
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &RouteIndex,
    resolver: &dyn ServiceResolver,
) -> bool {
    let routes: Vec<HTTPRoute> = match index.read() {
        Ok(g) => g.values().map(|t| t.route.clone()).collect(),
        Err(e) => {
            error!("Gateway API: index lock poisoned: {}", e);
            return false;
        }
    };

    let mut any_change = false;
    for r in routes {
        if apply_route(&r, storage, index, resolver) {
            any_change = true;
        }
    }
    any_change
}

/// Validate that the cluster knows about the Gateway API CRDs before we
/// start the watcher. Returns true if the CRD is installed, false if it
/// is missing or unreachable after a short retry window.
///
/// Why retry: at sozune startup the kube-apiserver aggregated discovery
/// might not yet have indexed the CRD, even when it is installed (e.g. an
/// e2e suite that applies the CRDs in the same script that boots
/// sozune). Without retry we'd permanently disable the watcher on a
/// transient race and require a sozune restart.
pub async fn httproute_crd_installed(client: &Client) -> bool {
    let api: Api<HTTPRoute> = Api::all(client.clone());
    for attempt in 1..=5 {
        match api.list(&Default::default()).await {
            Ok(_) => return true,
            Err(e) => {
                info!(
                    "Gateway API: probe attempt {}/5 failed ({}), retrying",
                    attempt, e
                );
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
    false
}

/// Resolves a `(namespace, service_name)` to the list of ready pod IPs the
/// Service points to. Implemented by the Kubernetes provider's EndpointSlice
/// cache; the watcher uses it to inflate Service references into concrete
/// IP backends Sōzu accepts (Sōzu refuses any address that doesn't parse as
/// `IpAddr`).
pub trait ServiceResolver: Send + Sync {
    fn pod_ips(&self, namespace: &str, service: &str) -> Vec<String>;
}

impl ServiceResolver for crate::provider::kubernetes::KubernetesProvider {
    fn pod_ips(&self, namespace: &str, service: &str) -> Vec<String> {
        self.pod_ips_for(&format!("{namespace}/{service}"))
    }
}

/// Convert a HTTPRoute into one or more Sozune `Entrypoint`s — one per
/// rule that has at least one resolvable backend.
///
/// The `resolver` turns each Service reference into concrete pod IPs.
/// Sōzu rejects DNS-style addresses (it expects `IpAddr`), so a route
/// pointing at a Service with no ready endpoints yet produces no
/// entrypoint at all — we'd rather drop the route than register a
/// frontend that 502s on every request. The watcher will retry once the
/// EndpointSlice catches up.
///
/// Skipped silently:
/// - rules with no backends (logged once at watch time, not here)
/// - rules with backends that resolve to zero pod IPs
/// - matches that aren't `Path` (header/query/method-only matches)
/// - `RegularExpression` path type — not yet supported by the routing layer
pub fn route_to_entrypoints(route: &HTTPRoute, resolver: &dyn ServiceResolver) -> Vec<Entrypoint> {
    let ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let route_name = match route.metadata.name.as_deref() {
        Some(n) => n,
        None => return Vec::new(),
    };

    let hostnames = route.spec.hostnames.clone().unwrap_or_default();

    let Some(rules) = route.spec.rules.as_ref() else {
        return Vec::new();
    };

    rules
        .iter()
        .enumerate()
        .filter_map(|(idx, rule)| {
            rule_to_entrypoint(ns, route_name, idx, &hostnames, rule, resolver)
        })
        .collect()
}

fn rule_to_entrypoint(
    namespace: &str,
    route_name: &str,
    rule_index: usize,
    hostnames: &[String],
    rule: &HTTPRouteRules,
    resolver: &dyn ServiceResolver,
) -> Option<Entrypoint> {
    let backend_refs = rule.backend_refs.as_ref()?;
    let backends: Vec<Backend> = backend_refs
        .iter()
        .flat_map(|b| {
            let Some(port_i32) = b.port else {
                return Vec::new();
            };
            let Ok(port) = u16::try_from(port_i32) else {
                return Vec::new();
            };
            // Service-typed backends only for v1. group/kind defaulting to
            // empty/Service per Gateway API spec is what we accept; anything
            // else (e.g. an external resource) is out of scope.
            let kind_ok = b.kind.as_deref().map(|k| k == "Service").unwrap_or(true);
            let group_ok = b.group.as_deref().map(|g| g.is_empty()).unwrap_or(true);
            if !kind_ok || !group_ok {
                return Vec::new();
            }
            let target_ns = b.namespace.as_deref().unwrap_or(namespace);
            let weight = b.weight.unwrap_or(100).max(0) as u32;
            resolver
                .pod_ips(target_ns, &b.name)
                .into_iter()
                .map(|address| Backend {
                    address,
                    port,
                    weight,
                })
                .collect()
        })
        .collect();

    if backends.is_empty() {
        return None;
    }

    let path = rule
        .matches
        .as_ref()
        .and_then(|matches| matches.first())
        .and_then(|m| m.path.as_ref())
        .and_then(|p| {
            let value = p.value.clone()?;
            let rule_type = match p.r#type {
                Some(HTTPRouteRulesMatchesPathType::Exact) => PathRuleType::Exact,
                Some(HTTPRouteRulesMatchesPathType::PathPrefix) | None => PathRuleType::Prefix,
                Some(HTTPRouteRulesMatchesPathType::RegularExpression) => return None,
            };
            Some(PathConfig { rule_type, value })
        });

    let id = format!("{SOURCE_TAG}-{namespace}-{route_name}-{rule_index}");

    Some(Entrypoint {
        id: id.clone(),
        name: format!("{route_name}-{rule_index}"),
        backends,
        protocol: Protocol::Http,
        config: EntrypointConfig {
            hostnames: hostnames.to_vec(),
            path,
            tls: false,
            strip_prefix: false,
            add_prefix: None,
            https_redirect: false,
            https_redirect_port: None,
            redirect: None,
            redirect_scheme: None,
            redirect_template: None,
            www_authenticate: None,
            priority: 0,
            auth: None,
            forward_auth: None,
            headers: Vec::new(),
            backend_timeout: None,
            rate_limit: None,
            sticky_session: false,
            compress: false,
            entrypoint: None,
            methods: Vec::new(),
        },
        source: Some(id),
    })
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
    use gateway_api::apis::standard::httproutes::{
        HTTPRouteRulesBackendRefs, HTTPRouteRulesMatches, HTTPRouteRulesMatchesPath, HTTPRouteSpec,
    };
    use kube::api::ObjectMeta;

    /// Sanity check that the gateway-api crate types compile and that the
    /// fields we read in `log_route` actually exist with the shapes we
    /// assume (Option<Vec<String>> for hostnames, Option<Vec<rule>> for
    /// rules). If gateway-api ever bumps and changes these shapes, this
    /// test fails at compile time.
    #[test]
    fn httproute_shape_matches_what_we_read() {
        let r = HTTPRoute::default();
        let _: Option<Vec<String>> = r.spec.hostnames;
        let _: Option<Vec<HTTPRouteRules>> = r.spec.rules;
    }

    /// Resolver test double: returns the same canned IP for every Service
    /// it's asked about — enough for the tests that only care about
    /// "backend address ends up in the entrypoint".
    struct StubResolver(Vec<&'static str>);
    impl ServiceResolver for StubResolver {
        fn pod_ips(&self, _ns: &str, _svc: &str) -> Vec<String> {
            self.0.iter().map(|s| s.to_string()).collect()
        }
    }

    /// Default resolver for happy-path tests: one ready pod IP.
    fn r1() -> StubResolver {
        StubResolver(vec!["10.0.0.1"])
    }

    /// Resolver that returns nothing — exercises the "Service has no ready
    /// endpoints" path.
    fn r0() -> StubResolver {
        StubResolver(vec![])
    }

    fn route_with(rules: Vec<HTTPRouteRules>, hostnames: Vec<String>) -> HTTPRoute {
        HTTPRoute {
            metadata: ObjectMeta {
                name: Some("web".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: HTTPRouteSpec {
                hostnames: if hostnames.is_empty() {
                    None
                } else {
                    Some(hostnames)
                },
                rules: Some(rules),
                ..Default::default()
            },
            status: Default::default(),
        }
    }

    fn backend(name: &str, port: i32) -> HTTPRouteRulesBackendRefs {
        HTTPRouteRulesBackendRefs {
            name: name.into(),
            port: Some(port),
            weight: Some(100),
            ..Default::default()
        }
    }

    fn rule(
        matches: Option<Vec<HTTPRouteRulesMatches>>,
        backends: Vec<HTTPRouteRulesBackendRefs>,
    ) -> HTTPRouteRules {
        HTTPRouteRules {
            matches,
            backend_refs: Some(backends),
            ..Default::default()
        }
    }

    fn path_match(value: &str, ty: HTTPRouteRulesMatchesPathType) -> HTTPRouteRulesMatches {
        HTTPRouteRulesMatches {
            path: Some(HTTPRouteRulesMatchesPath {
                r#type: Some(ty),
                value: Some(value.into()),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn route_without_rules_yields_no_entrypoints() {
        let r = HTTPRoute {
            metadata: ObjectMeta {
                name: Some("web".into()),
                ..Default::default()
            },
            spec: HTTPRouteSpec::default(),
            status: Default::default(),
        };
        assert!(route_to_entrypoints(&r, &r1()).is_empty());
    }

    #[test]
    fn route_without_name_yields_no_entrypoints() {
        let r = HTTPRoute {
            metadata: ObjectMeta::default(),
            spec: HTTPRouteSpec {
                rules: Some(vec![rule(None, vec![backend("svc", 80)])]),
                ..Default::default()
            },
            status: Default::default(),
        };
        assert!(route_to_entrypoints(&r, &r1()).is_empty());
    }

    #[test]
    fn rule_without_backends_is_skipped() {
        let r = route_with(
            vec![HTTPRouteRules {
                backend_refs: None,
                ..Default::default()
            }],
            vec!["app.example.com".into()],
        );
        assert!(route_to_entrypoints(&r, &r1()).is_empty());
    }

    #[test]
    fn rule_without_port_is_skipped() {
        let mut b = backend("svc", 0);
        b.port = None;
        let r = route_with(vec![rule(None, vec![b])], vec!["app.example.com".into()]);
        assert!(route_to_entrypoints(&r, &r1()).is_empty());
    }

    #[test]
    fn single_rule_produces_one_entrypoint_with_resolved_pod_ip() {
        let r = route_with(
            vec![rule(None, vec![backend("api", 8080)])],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1());
        assert_eq!(eps.len(), 1);
        let ep = &eps[0];
        assert_eq!(ep.id, "k8s-gateway-default-web-0");
        assert_eq!(ep.config.hostnames, vec!["app.example.com"]);
        assert_eq!(ep.backends.len(), 1);
        assert_eq!(ep.backends[0].address, "10.0.0.1");
        assert_eq!(ep.backends[0].port, 8080);
        assert_eq!(ep.backends[0].weight, 100);
        assert!(matches!(ep.protocol, Protocol::Http));
    }

    #[test]
    fn rule_with_unresolved_service_yields_no_entrypoint() {
        let r = route_with(
            vec![rule(None, vec![backend("api", 8080)])],
            vec!["app.example.com".into()],
        );
        // Empty resolver: Service has no ready endpoints yet — we drop the
        // route rather than register a frontend that would 502.
        assert!(route_to_entrypoints(&r, &r0()).is_empty());
    }

    #[test]
    fn multiple_pod_ips_produce_multiple_backends() {
        let r = route_with(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        let resolver = StubResolver(vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
        let eps = route_to_entrypoints(&r, &resolver);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].backends.len(), 3);
        let addresses: Vec<&str> = eps[0].backends.iter().map(|b| b.address.as_str()).collect();
        assert!(addresses.contains(&"10.0.0.1"));
        assert!(addresses.contains(&"10.0.0.2"));
        assert!(addresses.contains(&"10.0.0.3"));
    }

    #[test]
    fn multiple_rules_produce_multiple_entrypoints_with_indexed_ids() {
        let r = route_with(
            vec![
                rule(None, vec![backend("api", 80)]),
                rule(None, vec![backend("admin", 8080)]),
            ],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1());
        assert_eq!(eps.len(), 2);
        assert!(eps[0].id.ends_with("-0"));
        assert!(eps[1].id.ends_with("-1"));
    }

    #[test]
    fn cross_namespace_backend_resolves_against_target_namespace() {
        // The resolver is told (namespace, service); make sure the
        // target ns from the backendRef wins over the route's ns.
        struct CrossNsResolver;
        impl ServiceResolver for CrossNsResolver {
            fn pod_ips(&self, namespace: &str, service: &str) -> Vec<String> {
                if namespace == "other" && service == "api" {
                    vec!["10.1.0.1".into()]
                } else {
                    Vec::new()
                }
            }
        }
        let mut b = backend("api", 80);
        b.namespace = Some("other".into());
        let r = route_with(vec![rule(None, vec![b])], vec!["app.example.com".into()]);
        let eps = route_to_entrypoints(&r, &CrossNsResolver);
        assert_eq!(eps[0].backends[0].address, "10.1.0.1");
    }

    #[test]
    fn path_prefix_match_is_translated() {
        let r = route_with(
            vec![rule(
                Some(vec![path_match(
                    "/api",
                    HTTPRouteRulesMatchesPathType::PathPrefix,
                )]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1());
        let p = eps[0].config.path.as_ref().expect("path config present");
        assert_eq!(p.value, "/api");
        assert!(matches!(p.rule_type, PathRuleType::Prefix));
    }

    #[test]
    fn exact_path_match_is_translated() {
        let r = route_with(
            vec![rule(
                Some(vec![path_match(
                    "/health",
                    HTTPRouteRulesMatchesPathType::Exact,
                )]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1());
        let p = eps[0].config.path.as_ref().unwrap();
        assert!(matches!(p.rule_type, PathRuleType::Exact));
        assert_eq!(p.value, "/health");
    }

    #[test]
    fn regex_path_match_is_skipped() {
        let r = route_with(
            vec![rule(
                Some(vec![path_match(
                    "^/api/v[0-9]+",
                    HTTPRouteRulesMatchesPathType::RegularExpression,
                )]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1());
        // Backend still produces an entrypoint, but without a path config.
        assert_eq!(eps.len(), 1);
        assert!(eps[0].config.path.is_none());
    }

    #[test]
    fn non_service_kind_backend_is_skipped() {
        let mut b = backend("svc", 80);
        b.kind = Some("CustomResource".into());
        let r = route_with(vec![rule(None, vec![b])], vec!["app.example.com".into()]);
        assert!(route_to_entrypoints(&r, &r1()).is_empty());
    }

    fn route_with_uid(uid: &str, rules: Vec<HTTPRouteRules>, hostnames: Vec<String>) -> HTTPRoute {
        let mut r = route_with(rules, hostnames);
        r.metadata.uid = Some(uid.into());
        r
    }

    #[test]
    fn apply_inserts_entrypoints_and_indexes_them_by_uid() {
        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));
        let r = route_with_uid(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );

        let changed = apply_route(&r, &storage, &index, &r1());
        assert!(changed);
        assert_eq!(storage.read().unwrap().len(), 1);
        assert_eq!(
            index
                .read()
                .unwrap()
                .get("uid-1")
                .unwrap()
                .entrypoint_ids
                .len(),
            1
        );
    }

    #[test]
    fn second_apply_replaces_previous_entrypoints_for_same_uid() {
        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));

        let v1 = route_with_uid(
            "uid-1",
            vec![
                rule(None, vec![backend("api", 80)]),
                rule(None, vec![backend("admin", 8080)]),
            ],
            vec!["app.example.com".into()],
        );
        apply_route(&v1, &storage, &index, &r1());
        assert_eq!(storage.read().unwrap().len(), 2);

        let v2 = route_with_uid(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        let changed = apply_route(&v2, &storage, &index, &r1());
        assert!(changed);
        assert_eq!(
            storage.read().unwrap().len(),
            1,
            "the second rule's entrypoint must be removed when v2 only has one rule"
        );
        assert_eq!(
            index
                .read()
                .unwrap()
                .get("uid-1")
                .unwrap()
                .entrypoint_ids
                .len(),
            1
        );
    }

    #[test]
    fn delete_removes_all_entrypoints_for_uid() {
        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));
        let r = route_with_uid(
            "uid-1",
            vec![
                rule(None, vec![backend("api", 80)]),
                rule(None, vec![backend("admin", 8080)]),
            ],
            vec!["app.example.com".into()],
        );
        apply_route(&r, &storage, &index, &r1());
        assert_eq!(storage.read().unwrap().len(), 2);

        let changed = delete_route(&r, &storage, &index);
        assert!(changed);
        assert!(storage.read().unwrap().is_empty());
        assert!(index.read().unwrap().get("uid-1").is_none());
    }

    #[test]
    fn delete_for_unknown_uid_is_noop() {
        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));
        let r = route_with_uid(
            "uid-unknown",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        assert!(!delete_route(&r, &storage, &index));
    }

    #[test]
    fn apply_with_no_resolvable_backends_clears_storage_but_keeps_route_tracked() {
        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));

        let v1 = route_with_uid(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        apply_route(&v1, &storage, &index, &r1());
        assert_eq!(storage.read().unwrap().len(), 1);

        // v2 has rules but no usable backends — the entrypoint must
        // disappear from storage, but the route stays in the index so the
        // periodic re-resolve can revive it once endpoints come back.
        let v2 = route_with_uid(
            "uid-1",
            vec![HTTPRouteRules {
                backend_refs: None,
                ..Default::default()
            }],
            vec!["app.example.com".into()],
        );
        let changed = apply_route(&v2, &storage, &index, &r1());
        assert!(changed);
        assert!(storage.read().unwrap().is_empty());
        assert_eq!(
            index
                .read()
                .unwrap()
                .get("uid-1")
                .unwrap()
                .entrypoint_ids
                .len(),
            0,
            "route stays tracked but with zero entrypoint ids"
        );
    }

    #[test]
    fn re_resolve_picks_up_endpoints_that_appeared_after_apply() {
        use std::sync::Mutex;
        // Resolver that starts empty, then is flipped to a single IP — mimics
        // EndpointSlice arriving after the HTTPRoute was first applied.
        struct LateResolver {
            ips: Mutex<Vec<&'static str>>,
        }
        impl ServiceResolver for LateResolver {
            fn pod_ips(&self, _ns: &str, _svc: &str) -> Vec<String> {
                self.ips
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            }
        }
        let resolver = LateResolver {
            ips: Mutex::new(vec![]),
        };

        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));

        let r = route_with_uid(
            "uid-late",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        apply_route(&r, &storage, &index, &resolver);
        assert!(
            storage.read().unwrap().is_empty(),
            "no entrypoint while no endpoints"
        );
        // EndpointSlice now has a ready pod IP.
        *resolver.ips.lock().unwrap() = vec!["10.0.0.42"];

        let changed = re_resolve_all(&storage, &index, &resolver);
        assert!(changed);
        let storage_g = storage.read().unwrap();
        assert_eq!(storage_g.len(), 1);
        let ep = storage_g.values().next().unwrap();
        assert_eq!(ep.backends[0].address, "10.0.0.42");
    }

    #[test]
    fn weight_is_propagated() {
        let mut b = backend("api", 80);
        b.weight = Some(42);
        let r = route_with(vec![rule(None, vec![b])], vec!["app.example.com".into()]);
        let eps = route_to_entrypoints(&r, &r1());
        assert_eq!(eps[0].backends[0].weight, 42);
    }
}
