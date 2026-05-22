//! Kubernetes Gateway API watcher.
//!
//! Watches three Gateway API resources cluster-wide and pushes resolved
//! HTTP entrypoints into the shared storage:
//!
//!   - `GatewayClass` — accepted iff `spec.controllerName ==
//!     [`SOZUNE_CONTROLLER_NAME`]. Standard multi-controller scoping per
//!     Gateway API: every controller picks its own controllerName and
//!     ignores classes that point elsewhere. Without this filter we'd
//!     hijack routes meant for Traefik/Envoy/NGINX in any cluster running
//!     more than one Gateway implementation.
//!   - `Gateway` — accepted iff its `spec.gatewayClassName` references one
//!     of our accepted GatewayClasses.
//!   - `HTTPRoute` — accepted iff it has at least one `parentRefs` entry
//!     pointing to one of our accepted Gateways. Routes whose parents
//!     are not (yet) in scope stay tracked in memory but produce zero
//!     entrypoints, so they activate automatically once a matching
//!     Gateway appears (and deactivate when it disappears).
//!
//! Pairing with [`KubernetesProvider`](super::KubernetesProvider):
//! the existing provider keeps owning Service/Ingress/EndpointSlice. This
//! module owns Gateway API CRDs. The two run side by side and feed the
//! same shared storage through reload signals.
//!
//! References:
//!   - <https://gateway-api.sigs.k8s.io/api-types/httproute/>
//!   - <https://gateway-api.sigs.k8s.io/api-types/gatewayclass/>
//!   - <https://gateway-api.sigs.k8s.io/api-types/gateway/>

use crate::model::{Backend, Entrypoint, EntrypointConfig, PathConfig, PathRuleType, Protocol};
use futures_util::StreamExt;
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HTTPRouteParentRefs, HTTPRouteRules, HTTPRouteRulesMatches,
    HTTPRouteRulesMatchesPathType, HTTPRouteStatus, HTTPRouteStatusParents,
    HTTPRouteStatusParentsParentRef,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{Patch, PatchParams};
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, error, info, warn};

/// Single source of truth for sōzune's Gateway API controller identity.
/// A `GatewayClass` opts in to sōzune by setting `spec.controllerName` to
/// this exact string; everything else is ignored.
///
/// The format follows the Gateway API convention `<vendor>/<purpose>` so
/// it slots cleanly next to `traefik.io/gateway-controller`,
/// `gateway.envoyproxy.io/gatewayclass-controller`, and friends.
pub const SOZUNE_CONTROLLER_NAME: &str = "kemeter.io/sozune";

/// Group used in `parentRefs.group` for Gateway API resources. Empty or
/// unset is also accepted per spec (`gateway.networking.k8s.io` is
/// inferred when omitted).
const GATEWAY_API_GROUP: &str = "gateway.networking.k8s.io";

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

/// In-memory snapshot of the Gateway API resources sōzune has decided to
/// honour. The HTTPRoute watcher consults this on every apply to decide
/// whether a route is in scope; the GatewayClass and Gateway watchers
/// mutate it.
///
/// Keeping it as an explicit struct (rather than two free-standing
/// `RwLock`s) lets us atomically answer "is this route in scope?" in
/// constant time without partial views during concurrent updates.
#[derive(Default, Debug)]
pub struct ScopeState {
    /// Names of GatewayClasses whose `spec.controllerName` matches
    /// [`SOZUNE_CONTROLLER_NAME`]. Cluster-scoped, so a flat set is
    /// enough.
    gateway_classes: HashSet<String>,
    /// Gateways we accept, keyed by `(namespace, name)`. A Gateway is
    /// accepted iff `spec.gatewayClassName` is in `gateway_classes`. We
    /// don't yet read the listener list — that's a post-merge concern.
    gateways: HashSet<(String, String)>,
}

/// Thread-safe handle to the [`ScopeState`] paired with a notifier the
/// HTTPRoute watcher subscribes to. Mutating the scope notifies; the
/// HTTPRoute watcher reacts by re-resolving every tracked route, so a
/// freshly accepted Gateway activates dependent routes immediately
/// instead of waiting for the next 2-second tick.
///
/// Cheap to clone (Arc).
#[derive(Clone, Default)]
pub struct GatewayScope {
    state: Arc<RwLock<ScopeState>>,
    /// `notify_one` is debounce-friendly: bursts of GatewayClass/Gateway
    /// events collapse into a single re-resolve pass, matching how the
    /// outer reload pipeline already debounces.
    changed: Arc<Notify>,
}

impl GatewayScope {
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to scope changes. The returned future resolves every
    /// time a watcher mutates the accepted set.
    pub async fn changed(&self) {
        self.changed.notified().await
    }

    /// Returns true iff `parent_ref`, evaluated relative to a route in
    /// `route_namespace`, points to a Gateway sōzune currently owns. The
    /// kind/group rules follow the Gateway API spec: missing `kind`
    /// defaults to `Gateway`, missing `group` defaults to
    /// `gateway.networking.k8s.io`. A `parentRef` to a `Service` (mesh
    /// profile) is explicitly out of scope here.
    fn accepts_parent_ref(&self, route_namespace: &str, parent_ref: &HTTPRouteParentRefs) -> bool {
        let kind = parent_ref.kind.as_deref().unwrap_or("Gateway");
        if kind != "Gateway" {
            return false;
        }
        let group = parent_ref.group.as_deref().unwrap_or(GATEWAY_API_GROUP);
        // Empty string is a deliberate signal in the API ("core group");
        // we accept it the same way kubectl does for HTTPRoute parents.
        if !group.is_empty() && group != GATEWAY_API_GROUP {
            return false;
        }
        let ns = parent_ref.namespace.as_deref().unwrap_or(route_namespace);
        let key = (ns.to_string(), parent_ref.name.clone());
        match self.state.read() {
            Ok(g) => g.gateways.contains(&key),
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                false
            }
        }
    }

    /// True iff at least one of the route's `parentRefs` points to an
    /// accepted Gateway. A route with no parentRefs at all is rejected —
    /// Gateway API requires every Route to declare its parent(s).
    pub fn accepts_route(&self, route: &HTTPRoute) -> bool {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let Some(refs) = route.spec.parent_refs.as_ref() else {
            return false;
        };
        refs.iter().any(|p| self.accepts_parent_ref(route_ns, p))
    }

    /// Notifies subscribers iff `changed` is true; returns the same bool
    /// for caller convenience.
    fn fire_if(&self, changed: bool) -> bool {
        if changed {
            self.changed.notify_one();
        }
        changed
    }

    /// Mutates the scope on a GatewayClass apply. Returns true iff the
    /// accepted set actually changed (subscribers are notified). Cascades
    /// to the Gateway set: if a class flips out of scope, every Gateway
    /// pointing at it must also drop out.
    pub fn upsert_gateway_class(&self, class: &GatewayClass) -> bool {
        let Some(name) = class.metadata.name.as_deref() else {
            return false;
        };
        let accepted = class.spec.controller_name == SOZUNE_CONTROLLER_NAME;
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return false;
            }
        };
        let was = g.gateway_classes.contains(name);
        if accepted == was {
            return false;
        }
        if accepted {
            g.gateway_classes.insert(name.to_string());
        } else {
            g.gateway_classes.remove(name);
            // Drop every Gateway that depended on this class. We can't
            // tell from the snapshot which Gateway pointed where, so on a
            // class removal we simply force a re-evaluation by clearing
            // accepted Gateways — the Gateway watcher's relist on
            // reconnect (or the next event) will rebuild the set.
            //
            // In steady state classes don't churn, so this is a rare
            // and correct path: better than silently honouring a Gateway
            // whose class we no longer own.
            g.gateways.clear();
        }
        drop(g);
        self.fire_if(true)
    }

    pub fn remove_gateway_class(&self, name: &str) -> bool {
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return false;
            }
        };
        let removed = g.gateway_classes.remove(name);
        if removed {
            g.gateways.clear();
        }
        drop(g);
        self.fire_if(removed)
    }

    /// Mutates the scope on a Gateway apply. Returns true iff the
    /// accepted set actually changed.
    pub fn upsert_gateway(&self, gateway: &Gateway) -> bool {
        let Some(name) = gateway.metadata.name.as_deref() else {
            return false;
        };
        let ns = gateway
            .metadata
            .namespace
            .as_deref()
            .unwrap_or("default")
            .to_string();
        let class = gateway.spec.gateway_class_name.as_str();

        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return false;
            }
        };
        let key = (ns, name.to_string());
        let accepted = g.gateway_classes.contains(class);
        let was = g.gateways.contains(&key);
        let changed = match (accepted, was) {
            (true, false) => {
                g.gateways.insert(key);
                true
            }
            (false, true) => {
                g.gateways.remove(&key);
                true
            }
            _ => false,
        };
        drop(g);
        self.fire_if(changed)
    }

    pub fn remove_gateway(&self, namespace: &str, name: &str) -> bool {
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return false;
            }
        };
        let removed = g
            .gateways
            .remove(&(namespace.to_string(), name.to_string()));
        drop(g);
        self.fire_if(removed)
    }
}

/// Kick off a HTTPRoute watch on the given client. On every Apply we
/// upsert the produced entrypoints into shared storage; on Delete we
/// remove them. Each meaningful change emits a single `reload_tx` signal
/// — the proxy's debouncer collapses bursts.
///
/// The `scope` is consulted on every apply to skip routes whose
/// `parentRefs` don't match a sōzune-owned Gateway. Routes out of scope
/// stay tracked in memory so they activate the moment a matching Gateway
/// appears (or deactivate when one disappears).
pub async fn run_httproute_watcher(
    client: Client,
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    reload_tx: mpsc::Sender<()>,
    resolver: Arc<dyn ServiceResolver>,
    scope: GatewayScope,
) -> anyhow::Result<()> {
    // Spawn the status writer in a dedicated task. Buffer chosen
    // empirically: enough headroom for an apiserver burst (a relist on
    // reconnect can replay hundreds of routes in a few hundred ms),
    // small enough that we drop quietly under sustained load rather
    // than holding everything in memory. Lost status writes are
    // observability-only; routing keeps working.
    let (status_tx, status_rx) = mpsc::channel::<(HTTPRoute, RouteOutcome)>(256);
    {
        let client = client.clone();
        let scope = scope.clone();
        tokio::spawn(async move {
            run_status_writer(client, status_rx, scope).await;
        });
    }

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
                    apply_route(&route, &storage, &index, resolver.as_ref(), &scope, Some(&status_tx))
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
                re_resolve_all(&storage, &index, resolver.as_ref(), &scope, Some(&status_tx))
            }
            // A new Gateway/GatewayClass was accepted (or one we owned
            // was removed). Routes pointing at it must flip in/out of
            // scope right now — without this, we'd wait up to 2 s for
            // the next tick to propagate the change.
            _ = scope.changed() => {
                debug!("Gateway API: scope changed, re-resolving routes");
                re_resolve_all(&storage, &index, resolver.as_ref(), &scope, Some(&status_tx))
            }
        };
        if changed && let Err(e) = reload_tx.send(()).await {
            error!("Gateway API: failed to send reload signal: {}", e);
        }
    }

    warn!("Gateway API: HTTPRoute watcher stream ended unexpectedly");
    Ok(())
}

/// Watch GatewayClasses cluster-wide and keep [`GatewayScope`] in sync.
/// Cluster-scoped resource: no namespace selector.
///
/// On stream errors we log and let the [`watcher::watcher`] driver
/// reconnect — its built-in backoff is enough for transient apiserver
/// hiccups, and the relist on reconnect rebuilds the accepted set
/// correctly even if we missed events while disconnected.
pub async fn run_gatewayclass_watcher(client: Client, scope: GatewayScope) -> anyhow::Result<()> {
    let api: Api<GatewayClass> = Api::all(client);
    let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();
    info!("Gateway API: GatewayClass watcher started");

    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Apply(class)) | Ok(Event::InitApply(class)) => {
                let name = class.metadata.name.as_deref().unwrap_or("<no-name>");
                let accepted = class.spec.controller_name == SOZUNE_CONTROLLER_NAME;
                if scope.upsert_gateway_class(&class) {
                    info!(
                        "Gateway API: GatewayClass {} {} (controllerName={})",
                        name,
                        if accepted { "accepted" } else { "rejected" },
                        class.spec.controller_name
                    );
                }
            }
            Ok(Event::Delete(class)) => {
                if let Some(name) = class.metadata.name.as_deref()
                    && scope.remove_gateway_class(name)
                {
                    info!("Gateway API: GatewayClass {} removed", name);
                }
            }
            Ok(Event::Init) => debug!("Gateway API: GatewayClass init"),
            Ok(Event::InitDone) => debug!("Gateway API: GatewayClass init done"),
            Err(e) => error!("Gateway API: GatewayClass watcher error: {}", e),
        }
    }

    warn!("Gateway API: GatewayClass watcher stream ended unexpectedly");
    Ok(())
}

/// Watch Gateways cluster-wide and keep [`GatewayScope`] in sync. A
/// Gateway is accepted iff its `spec.gatewayClassName` matches one of the
/// GatewayClasses sōzune already accepted; the scope stitches the two
/// together transparently.
pub async fn run_gateway_watcher(client: Client, scope: GatewayScope) -> anyhow::Result<()> {
    let api: Api<Gateway> = Api::all(client);
    let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();
    info!("Gateway API: Gateway watcher started");

    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Apply(gw)) | Ok(Event::InitApply(gw)) => {
                let name = gw.metadata.name.as_deref().unwrap_or("<no-name>");
                let ns = gw.metadata.namespace.as_deref().unwrap_or("<no-namespace>");
                let class = gw.spec.gateway_class_name.clone();
                if scope.upsert_gateway(&gw) {
                    info!(
                        "Gateway API: Gateway {}/{} accepted (gatewayClassName={})",
                        ns, name, class
                    );
                }
            }
            Ok(Event::Delete(gw)) => {
                let name = gw.metadata.name.as_deref().unwrap_or("");
                let ns = gw.metadata.namespace.as_deref().unwrap_or("default");
                if !name.is_empty() && scope.remove_gateway(ns, name) {
                    info!("Gateway API: Gateway {}/{} removed", ns, name);
                }
            }
            Ok(Event::Init) => debug!("Gateway API: Gateway init"),
            Ok(Event::InitDone) => debug!("Gateway API: Gateway init done"),
            Err(e) => error!("Gateway API: Gateway watcher error: {}", e),
        }
    }

    warn!("Gateway API: Gateway watcher stream ended unexpectedly");
    Ok(())
}

/// Drains [`HTTPRoute`] outcomes from the watcher and patches the
/// `parents[]` slice of `status` that sōzune owns, leaving every other
/// controller's slice untouched. Conformance with Gateway API's status
/// model: every implementation MUST report at minimum the `Accepted`
/// condition for each parent it manages.
///
/// Failure modes are non-fatal — a 4xx (e.g. the route was deleted
/// between dispatch and PATCH) or 5xx (transient apiserver hiccup) is
/// logged at `warn` and dropped. The next re-resolve will retry. We
/// intentionally do **not** retry-with-backoff in this loop: routing
/// keeps working without status, and a tight retry loop here would mask
/// genuine apiserver issues that deserve operator attention.
async fn run_status_writer(
    client: Client,
    mut rx: mpsc::Receiver<(HTTPRoute, RouteOutcome)>,
    scope: GatewayScope,
) {
    info!("Gateway API: HTTPRoute status writer started");
    while let Some((route, outcome)) = rx.recv().await {
        let Some(name) = route.metadata.name.as_deref() else {
            continue;
        };
        let ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let our_status = build_route_status(&route, &scope, outcome);
        let (merged, changed) = merge_route_status(route.status.as_ref(), our_status);
        if !changed {
            continue;
        }

        // Build the minimal status patch — only the `parents` field of
        // `status`, as a strategic-merge JSON patch. This still
        // overwrites the whole array (Kubernetes doesn't deep-merge
        // arrays), but `merged` already contains every other
        // controller's slice unchanged, so we can't clobber them.
        let patch = serde_json::json!({
            "status": { "parents": merged }
        });
        let api: Api<HTTPRoute> = Api::namespaced(client.clone(), ns);
        let pp = PatchParams::default();
        if let Err(e) = api.patch_status(name, &pp, &Patch::Merge(&patch)).await {
            warn!(
                "Gateway API: failed to patch status on HTTPRoute {}/{}: {}",
                ns, name, e
            );
        } else {
            debug!(
                "Gateway API: status patched on HTTPRoute {}/{} (outcome={:?})",
                ns, name, outcome
            );
        }
    }
    info!("Gateway API: HTTPRoute status writer stopped");
}

/// Returns true if storage was modified. Replaces any previous state for
/// this route UID atomically so a rename of a rule doesn't leave a stale
/// entrypoint behind. Always remembers the route in the index so a later
/// EndpointSlice update — or a Gateway becoming accepted — can re-resolve
/// it, even when this apply produced zero entrypoints (Service had no
/// ready endpoints yet, or the route's parent isn't sōzune-owned).
fn apply_route(
    route: &HTTPRoute,
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &RouteIndex,
    resolver: &dyn ServiceResolver,
    scope: &GatewayScope,
    status_tx: Option<&mpsc::Sender<(HTTPRoute, RouteOutcome)>>,
) -> bool {
    let uid = match route.metadata.uid.as_deref() {
        Some(u) => u.to_string(),
        None => {
            warn!("Gateway API: HTTPRoute without uid, skipping");
            return false;
        }
    };

    // Out-of-scope routes are tracked but produce zero entrypoints, so
    // they activate the moment a matching Gateway appears (via
    // re_resolve_all from the Gateway watcher) and deactivate cleanly
    // when one disappears.
    //
    // Routes that declare unsupported filters (requestRedirect,
    // urlRewrite, header modifiers, mirror, etc.) are also dropped:
    // routing them as if the filter wasn't there would silently rewrite
    // user intent. Worse than refusing the route — better to surface
    // the problem so the user knows to fall back to Ingress annotations
    // until filter support lands.
    let (outcome, new_entrypoints) = if !scope.accepts_route(route) {
        (RouteOutcome::NotMine, Vec::new())
    } else if route_has_unsupported_filters(route) {
        let ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let name = route.metadata.name.as_deref().unwrap_or("<no-name>");
        warn!(
            "Gateway API: HTTPRoute {}/{} declares filters (requestRedirect / urlRewrite / header modifiers / mirror) which sōzune does not support yet — dropping the route",
            ns, name
        );
        (RouteOutcome::UnsupportedFilters, Vec::new())
    } else {
        let eps = route_to_entrypoints(route, resolver);
        let outcome = if eps.is_empty() {
            RouteOutcome::NoResolvableBackends
        } else {
            RouteOutcome::Accepted
        };
        (outcome, eps)
    };

    // Best-effort status notification. We send the route (cloned —
    // tiny payload relative to the network round-trip) to the status
    // writer; it computes the desired status, deduplicates against the
    // current object, and PATCHes only when something changed. Send
    // failures are non-fatal: status is observability, not routing.
    if let Some(tx) = status_tx
        && let Err(e) = tx.try_send((route.clone(), outcome))
    {
        debug!("Gateway API: status channel full or closed: {}", e);
    }

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

/// Re-resolve every tracked route's entrypoints. Called both periodically
/// (so EndpointSlice churn — a Service that just got its first ready pod,
/// or a scale-down — eventually reaches Sōzu) and synchronously by the
/// Gateway/GatewayClass watchers when the scope changes (so routes flip
/// in/out of scope without waiting for the next tick). Returns true if
/// any route changed.
fn re_resolve_all(
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &RouteIndex,
    resolver: &dyn ServiceResolver,
    scope: &GatewayScope,
    status_tx: Option<&mpsc::Sender<(HTTPRoute, RouteOutcome)>>,
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
        if apply_route(&r, storage, index, resolver, scope, status_tx) {
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

/// Convert a HTTPRoute into one or more Sozune `Entrypoint`s. Each rule
/// expands to one entrypoint per `match` it declares (Gateway API
/// semantics: matches inside a rule are OR'd together). A rule with no
/// matches is treated as match-all, producing exactly one entrypoint
/// with no path constraint.
///
/// The `resolver` turns each Service reference into concrete pod IPs.
/// Sōzu rejects DNS-style addresses (it expects `IpAddr`), so a route
/// pointing at a Service with no ready endpoints yet produces no
/// entrypoint at all — we'd rather drop the route than register a
/// frontend that 502s on every request. The watcher will retry once the
/// EndpointSlice catches up.
///
/// Rules are dropped (with a `warn!`) when they declare any
/// `spec.rules[].filters` — silently honouring them would route as if
/// the filter wasn't there, which is *worse* than dropping the route
/// outright (the user would see traffic flowing but with the wrong
/// shape, e.g. no `requestRedirect`). Once we implement filters this
/// rejection lifts. See [`route_has_unsupported_filters`].
///
/// Other silent skips:
/// - rules with no backends
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
        .flat_map(|(idx, rule)| {
            rule_to_entrypoints(ns, route_name, idx, &hostnames, rule, resolver)
        })
        .collect()
}

/// True iff at least one rule in the route declares filters sōzune
/// can't faithfully execute today. The HTTPRoute watcher uses this as
/// an early reject so the user sees a clear log line and a
/// `ResolvedRefs=False` status condition rather than wrong behaviour.
pub fn route_has_unsupported_filters(route: &HTTPRoute) -> bool {
    route
        .spec
        .rules
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|rule| {
            rule.filters
                .as_deref()
                .map(|f| !f.is_empty())
                .unwrap_or(false)
        })
}

// Gateway API standard condition types and reasons. Values are the
// strings consumers (kubectl, gateway-api conformance suite) expect —
// don't paraphrase them.
const CONDITION_TYPE_ACCEPTED: &str = "Accepted";
const CONDITION_TYPE_RESOLVED_REFS: &str = "ResolvedRefs";
const REASON_ACCEPTED: &str = "Accepted";
const REASON_RESOLVED_REFS: &str = "ResolvedRefs";
const REASON_UNSUPPORTED_VALUE: &str = "UnsupportedValue";
const REASON_BACKEND_NOT_FOUND: &str = "BackendNotFound";

/// What the watcher decided about a route, computed once and used both
/// for log output and for the status conditions written back to the
/// apiserver. Centralising the decision in one enum keeps log/status
/// consistent: the user sees the same explanation in `kubectl describe`
/// as in sōzune's logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteOutcome {
    /// Route is in scope and produced at least one entrypoint.
    Accepted,
    /// At least one parentRef points to a sōzune-owned Gateway, but
    /// the route declares filters we don't support yet, so we dropped
    /// the entire route. Reflected as `ResolvedRefs=False
    /// reason=UnsupportedValue`.
    UnsupportedFilters,
    /// In scope, no filters, but every backendRef resolved to zero
    /// ready endpoints. Surfaces as `ResolvedRefs=False
    /// reason=BackendNotFound` so users can distinguish "I'm waiting
    /// on pods" from "my route is wrong".
    NoResolvableBackends,
    /// None of the route's parentRefs matched a sōzune-owned Gateway
    /// (or the route declares no parentRefs at all). We don't write a
    /// status entry in this case — Gateway API says implementations
    /// only populate `parents[]` for parents they own.
    NotMine,
}

/// Build the slice of `parents[]` entries sōzune owns for a given
/// route+outcome. Other controllers' entries must be preserved by the
/// caller (see [`merge_route_status`]).
///
/// One entry per parentRef that resolves to a Gateway sōzune accepts.
/// `Accepted=True` iff [`RouteOutcome::Accepted`]. `ResolvedRefs=True`
/// only when the outcome is `Accepted` (filters and unresolved
/// backends both flip it to False with distinct reasons).
fn build_route_status(
    route: &HTTPRoute,
    scope: &GatewayScope,
    outcome: RouteOutcome,
) -> Vec<HTTPRouteStatusParents> {
    if outcome == RouteOutcome::NotMine {
        return Vec::new();
    }
    let now = Time(k8s_openapi::chrono::Utc::now());
    let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let generation = route.metadata.generation;

    let (accepted_status, accepted_reason, accepted_msg) = match outcome {
        RouteOutcome::Accepted | RouteOutcome::NoResolvableBackends => (
            "True",
            REASON_ACCEPTED,
            "Route accepted by sōzune".to_string(),
        ),
        RouteOutcome::UnsupportedFilters => (
            "False",
            REASON_UNSUPPORTED_VALUE,
            "Route declares HTTPRoute filters which sōzune does not support yet (requestRedirect, urlRewrite, header modifiers, mirror)".to_string(),
        ),
        RouteOutcome::NotMine => unreachable!("filtered out above"),
    };
    let (refs_status, refs_reason, refs_msg) = match outcome {
        RouteOutcome::Accepted => (
            "True",
            REASON_RESOLVED_REFS,
            "All backendRefs resolved to ready endpoints".to_string(),
        ),
        RouteOutcome::UnsupportedFilters => (
            "False",
            REASON_UNSUPPORTED_VALUE,
            "Route filters are not supported".to_string(),
        ),
        RouteOutcome::NoResolvableBackends => (
            "False",
            REASON_BACKEND_NOT_FOUND,
            "No ready endpoints found for one or more backendRefs".to_string(),
        ),
        RouteOutcome::NotMine => unreachable!("filtered out above"),
    };

    route
        .spec
        .parent_refs
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|p| scope.accepts_parent_ref(route_ns, p))
        .map(|p| HTTPRouteStatusParents {
            controller_name: SOZUNE_CONTROLLER_NAME.to_string(),
            parent_ref: HTTPRouteStatusParentsParentRef {
                group: p.group.clone(),
                kind: p.kind.clone(),
                name: p.name.clone(),
                namespace: p.namespace.clone(),
                port: p.port,
                section_name: p.section_name.clone(),
            },
            conditions: Some(vec![
                Condition {
                    type_: CONDITION_TYPE_ACCEPTED.to_string(),
                    status: accepted_status.to_string(),
                    reason: accepted_reason.to_string(),
                    message: accepted_msg.clone(),
                    last_transition_time: now.clone(),
                    observed_generation: generation,
                },
                Condition {
                    type_: CONDITION_TYPE_RESOLVED_REFS.to_string(),
                    status: refs_status.to_string(),
                    reason: refs_reason.to_string(),
                    message: refs_msg.clone(),
                    last_transition_time: now.clone(),
                    observed_generation: generation,
                },
            ]),
        })
        .collect()
}

/// Merge sōzune's slice of `parents[]` into the route's existing
/// status, preserving entries owned by other controllers (matched on
/// `controllerName`). Returns the new full `parents[]` and a bool
/// indicating whether anything changed compared to what was on the
/// object — callers use that to skip no-op writes.
fn merge_route_status(
    existing: Option<&HTTPRouteStatus>,
    ours: Vec<HTTPRouteStatusParents>,
) -> (Vec<HTTPRouteStatusParents>, bool) {
    let existing_parents: &[HTTPRouteStatusParents] =
        existing.map(|s| s.parents.as_slice()).unwrap_or_default();
    let foreign: Vec<HTTPRouteStatusParents> = existing_parents
        .iter()
        .filter(|p| p.controller_name != SOZUNE_CONTROLLER_NAME)
        .cloned()
        .collect();
    let our_existing: Vec<&HTTPRouteStatusParents> = existing_parents
        .iter()
        .filter(|p| p.controller_name == SOZUNE_CONTROLLER_NAME)
        .collect();

    // Skip the write if our slice is byte-for-byte equivalent (modulo
    // last_transition_time, which we recompute every call). Comparing
    // conditions field-by-field with the timestamp ignored avoids
    // hammering the apiserver on every periodic re-resolve.
    let unchanged = our_existing.len() == ours.len()
        && our_existing.iter().zip(ours.iter()).all(|(a, b)| {
            a.parent_ref == b.parent_ref
                && conditions_equivalent(a.conditions.as_deref(), b.conditions.as_deref())
        });

    let mut merged = foreign;
    merged.extend(ours);
    (merged, !unchanged)
}

/// Two condition lists are equivalent for change-detection purposes if
/// they have the same (type, status, reason, message, observed_generation)
/// for every type — `last_transition_time` is regenerated on every call
/// and would otherwise force a write on every re-resolve.
fn conditions_equivalent(a: Option<&[Condition]>, b: Option<&[Condition]>) -> bool {
    let a = a.unwrap_or_default();
    let b = b.unwrap_or_default();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(c1, c2)| {
        c1.type_ == c2.type_
            && c1.status == c2.status
            && c1.reason == c2.reason
            && c1.message == c2.message
            && c1.observed_generation == c2.observed_generation
    })
}

fn rule_to_entrypoints(
    namespace: &str,
    route_name: &str,
    rule_index: usize,
    hostnames: &[String],
    rule: &HTTPRouteRules,
    resolver: &dyn ServiceResolver,
) -> Vec<Entrypoint> {
    // Gateway API: each entry in `filters` is meant to mutate the
    // request before it reaches the backend. Routing without honouring
    // them silently rewrites user intent — refuse the rule entirely
    // until we implement filter support.
    if let Some(filters) = rule.filters.as_deref()
        && !filters.is_empty()
    {
        return Vec::new();
    }

    let Some(backend_refs) = rule.backend_refs.as_ref() else {
        return Vec::new();
    };
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
        return Vec::new();
    }

    // Gateway API: matches inside a rule are OR'd. Emit one entrypoint
    // per match. A rule with no matches at all is "match anything" —
    // emit a single entrypoint with no path constraint to preserve that
    // semantic.
    let matches: Vec<Option<&HTTPRouteRulesMatches>> = match rule.matches.as_deref() {
        Some(ms) if !ms.is_empty() => ms.iter().map(Some).collect(),
        _ => vec![None],
    };
    let single_match = matches.len() == 1;

    matches
        .into_iter()
        .enumerate()
        .map(|(match_index, m)| {
            let path = m.and_then(|m| m.path.as_ref()).and_then(|p| {
                let value = p.value.clone()?;
                let rule_type = match p.r#type {
                    Some(HTTPRouteRulesMatchesPathType::Exact) => PathRuleType::Exact,
                    Some(HTTPRouteRulesMatchesPathType::PathPrefix) | None => PathRuleType::Prefix,
                    Some(HTTPRouteRulesMatchesPathType::RegularExpression) => return None,
                };
                Some(PathConfig { rule_type, value })
            });

            // Stable IDs: keep the existing `…-{rule_index}` shape when a
            // rule has exactly one match (the universal case until now,
            // and what the storage / dashboard expects), and append
            // `-m{match_index}` only when the rule fans out into
            // multiple matches.
            let id = if single_match {
                format!("{SOURCE_TAG}-{namespace}-{route_name}-{rule_index}")
            } else {
                format!("{SOURCE_TAG}-{namespace}-{route_name}-{rule_index}-m{match_index}")
            };
            let name = if single_match {
                format!("{route_name}-{rule_index}")
            } else {
                format!("{route_name}-{rule_index}-m{match_index}")
            };

            Entrypoint {
                id: id.clone(),
                name,
                backends: backends.clone(),
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
                    acme: None,
                },
                source: Some(id),
            }
        })
        .collect()
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
    use gateway_api::apis::standard::gatewayclasses::GatewayClassSpec;
    use gateway_api::apis::standard::gateways::GatewaySpec;
    use gateway_api::apis::standard::httproutes::{
        HTTPRouteRulesBackendRefs, HTTPRouteRulesMatches, HTTPRouteRulesMatchesPath, HTTPRouteSpec,
    };
    use kube::api::ObjectMeta;

    /// Builds a [`GatewayScope`] pre-populated with one accepted
    /// GatewayClass (`sozune`) and one accepted Gateway (`default/gw`).
    /// Tests that exercise `apply_route` / `re_resolve_all` use this so
    /// the route they construct (which points to `default/gw` via
    /// `route_with*`) is in scope by default. Tests that want to verify
    /// out-of-scope behaviour build their own scope.
    fn default_scope() -> GatewayScope {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&GatewayClass {
            metadata: ObjectMeta {
                name: Some("sozune".into()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: SOZUNE_CONTROLLER_NAME.into(),
                ..Default::default()
            },
            status: Default::default(),
        });
        scope.upsert_gateway(&Gateway {
            metadata: ObjectMeta {
                name: Some("gw".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "sozune".into(),
                ..Default::default()
            },
            status: Default::default(),
        });
        scope
    }

    /// Single parentRef pointing at `default/gw` — the Gateway
    /// `default_scope()` accepts. Helper because most route fixtures
    /// just want "this route is in scope, please".
    fn parent_default_gw() -> HTTPRouteParentRefs {
        HTTPRouteParentRefs {
            name: "gw".into(),
            ..Default::default()
        }
    }

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

    /// Default route fixture: namespace `default`, name `web`, one
    /// `parentRef` to the Gateway that `default_scope()` accepts so the
    /// route is in scope without ceremony. Tests that need a different
    /// parent build the route directly or use [`route_with_parents`].
    fn route_with(rules: Vec<HTTPRouteRules>, hostnames: Vec<String>) -> HTTPRoute {
        route_with_parents(rules, hostnames, vec![parent_default_gw()])
    }

    fn route_with_parents(
        rules: Vec<HTTPRouteRules>,
        hostnames: Vec<String>,
        parent_refs: Vec<HTTPRouteParentRefs>,
    ) -> HTTPRoute {
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
                parent_refs: if parent_refs.is_empty() {
                    None
                } else {
                    Some(parent_refs)
                },
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
        let scope = default_scope();
        let r = route_with_uid(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );

        let changed = apply_route(&r, &storage, &index, &r1(), &scope, None);
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
        let scope = default_scope();

        let v1 = route_with_uid(
            "uid-1",
            vec![
                rule(None, vec![backend("api", 80)]),
                rule(None, vec![backend("admin", 8080)]),
            ],
            vec!["app.example.com".into()],
        );
        apply_route(&v1, &storage, &index, &r1(), &scope, None);
        assert_eq!(storage.read().unwrap().len(), 2);

        let v2 = route_with_uid(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        let changed = apply_route(&v2, &storage, &index, &r1(), &scope, None);
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
        let scope = default_scope();
        let r = route_with_uid(
            "uid-1",
            vec![
                rule(None, vec![backend("api", 80)]),
                rule(None, vec![backend("admin", 8080)]),
            ],
            vec!["app.example.com".into()],
        );
        apply_route(&r, &storage, &index, &r1(), &scope, None);
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
        let scope = default_scope();

        let v1 = route_with_uid(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        apply_route(&v1, &storage, &index, &r1(), &scope, None);
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
        let changed = apply_route(&v2, &storage, &index, &r1(), &scope, None);
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
        let scope = default_scope();

        let r = route_with_uid(
            "uid-late",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        apply_route(&r, &storage, &index, &resolver, &scope, None);
        assert!(
            storage.read().unwrap().is_empty(),
            "no entrypoint while no endpoints"
        );
        // EndpointSlice now has a ready pod IP.
        *resolver.ips.lock().unwrap() = vec!["10.0.0.42"];

        let changed = re_resolve_all(&storage, &index, &resolver, &scope, None);
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

    // ---------- Filters & multi-match tests ----------

    use gateway_api::apis::standard::httproutes::HTTPRouteRulesFilters;

    fn rule_with_filter(
        backends: Vec<HTTPRouteRulesBackendRefs>,
        filters: Vec<HTTPRouteRulesFilters>,
    ) -> HTTPRouteRules {
        HTTPRouteRules {
            backend_refs: Some(backends),
            filters: if filters.is_empty() {
                None
            } else {
                Some(filters)
            },
            ..Default::default()
        }
    }

    #[test]
    fn route_with_any_filter_is_dropped_entirely() {
        // Honouring a filter we don't understand is worse than refusing
        // the route — silently routing as if the filter weren't there
        // breaks user intent.
        let r = route_with(
            vec![rule_with_filter(
                vec![backend("api", 80)],
                vec![HTTPRouteRulesFilters::default()],
            )],
            vec!["app.example.com".into()],
        );
        assert!(route_to_entrypoints(&r, &r1()).is_empty());
        assert!(route_has_unsupported_filters(&r));
    }

    #[test]
    fn route_with_empty_filter_list_still_routes() {
        // A non-None but empty filters slice means "no filters declared"
        // and must not trigger the rejection path.
        let r = route_with(
            vec![rule_with_filter(vec![backend("api", 80)], vec![])],
            vec!["app.example.com".into()],
        );
        assert!(!route_has_unsupported_filters(&r));
        assert_eq!(route_to_entrypoints(&r, &r1()).len(), 1);
    }

    #[test]
    fn rule_with_multiple_matches_emits_one_entrypoint_per_match() {
        // Gateway API treats matches inside one rule as OR. The old
        // behaviour silently dropped everything past the first match.
        let r = route_with(
            vec![rule(
                Some(vec![
                    path_match("/api", HTTPRouteRulesMatchesPathType::PathPrefix),
                    path_match("/v2", HTTPRouteRulesMatchesPathType::PathPrefix),
                    path_match("/healthz", HTTPRouteRulesMatchesPathType::Exact),
                ]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1());
        assert_eq!(eps.len(), 3, "one entrypoint per match");
        let paths: Vec<&str> = eps
            .iter()
            .map(|e| e.config.path.as_ref().unwrap().value.as_str())
            .collect();
        assert!(paths.contains(&"/api"));
        assert!(paths.contains(&"/v2"));
        assert!(paths.contains(&"/healthz"));
        // Multi-match entrypoints share backends (cloned, not aliased).
        for ep in &eps {
            assert_eq!(ep.backends[0].address, "10.0.0.1");
        }
        // IDs disambiguated with `-m{idx}` suffix only when >1 match —
        // single-match rules keep the legacy `-{rule_idx}` shape.
        assert_eq!(eps[0].id, "k8s-gateway-default-web-0-m0");
        assert_eq!(eps[1].id, "k8s-gateway-default-web-0-m1");
        assert_eq!(eps[2].id, "k8s-gateway-default-web-0-m2");
    }

    #[test]
    fn single_match_keeps_legacy_id_shape() {
        // Existing storage / dashboards expect `…-{rule_idx}` for
        // single-match rules. Don't break that.
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
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].id, "k8s-gateway-default-web-0");
    }

    #[test]
    fn rule_with_no_matches_is_match_all() {
        // Gateway API: a rule with no matches matches every request.
        // Emit exactly one entrypoint with no path constraint.
        let r = route_with(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1());
        assert_eq!(eps.len(), 1);
        assert!(eps[0].config.path.is_none());
    }

    // ---------- Status tests ----------
    //
    // The status writer touches an apiserver, so we don't test it
    // end-to-end here — the e2e suite does. We do test the two pure
    // helpers `build_route_status` and `merge_route_status` because
    // they encode the conformance contract: which conditions sōzune
    // owns, with which reasons, and how to slot them into a
    // multi-controller status without clobbering anyone.

    fn route_with_uid_parents(
        uid: &str,
        rules: Vec<HTTPRouteRules>,
        hostnames: Vec<String>,
        parent_refs: Vec<HTTPRouteParentRefs>,
    ) -> HTTPRoute {
        let mut r = route_with_parents(rules, hostnames, parent_refs);
        r.metadata.uid = Some(uid.into());
        r
    }

    fn condition(parents: &[HTTPRouteStatusParents], idx: usize, ty: &str) -> Condition {
        parents[idx]
            .conditions
            .as_ref()
            .unwrap()
            .iter()
            .find(|c| c.type_ == ty)
            .expect("expected condition not found")
            .clone()
    }

    #[test]
    fn build_status_for_accepted_route_emits_two_true_conditions() {
        let scope = default_scope();
        let r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent_default_gw()],
        );
        let parents = build_route_status(&r, &scope, RouteOutcome::Accepted);
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].controller_name, SOZUNE_CONTROLLER_NAME);
        assert_eq!(parents[0].parent_ref.name, "gw");

        let accepted = condition(&parents, 0, CONDITION_TYPE_ACCEPTED);
        assert_eq!(accepted.status, "True");
        assert_eq!(accepted.reason, REASON_ACCEPTED);

        let resolved = condition(&parents, 0, CONDITION_TYPE_RESOLVED_REFS);
        assert_eq!(resolved.status, "True");
        assert_eq!(resolved.reason, REASON_RESOLVED_REFS);
    }

    #[test]
    fn build_status_for_unsupported_filters_flips_both_to_false() {
        let scope = default_scope();
        let r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent_default_gw()],
        );
        let parents = build_route_status(&r, &scope, RouteOutcome::UnsupportedFilters);
        assert_eq!(
            condition(&parents, 0, CONDITION_TYPE_ACCEPTED).status,
            "False"
        );
        assert_eq!(
            condition(&parents, 0, CONDITION_TYPE_ACCEPTED).reason,
            REASON_UNSUPPORTED_VALUE
        );
        assert_eq!(
            condition(&parents, 0, CONDITION_TYPE_RESOLVED_REFS).status,
            "False"
        );
    }

    #[test]
    fn build_status_for_no_resolvable_backends_keeps_accepted_true() {
        // The route is OK at the gateway level — pods just aren't ready
        // yet. This is the most subtle case: `Accepted=True` so the
        // user knows the route is wired up, but `ResolvedRefs=False
        // reason=BackendNotFound` so they know why no traffic is
        // flowing.
        let scope = default_scope();
        let r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent_default_gw()],
        );
        let parents = build_route_status(&r, &scope, RouteOutcome::NoResolvableBackends);
        assert_eq!(
            condition(&parents, 0, CONDITION_TYPE_ACCEPTED).status,
            "True"
        );
        assert_eq!(
            condition(&parents, 0, CONDITION_TYPE_RESOLVED_REFS).status,
            "False"
        );
        assert_eq!(
            condition(&parents, 0, CONDITION_TYPE_RESOLVED_REFS).reason,
            REASON_BACKEND_NOT_FOUND
        );
    }

    #[test]
    fn build_status_for_not_mine_emits_no_entries() {
        // Gateway API: we MUST NOT report status for parents we don't
        // own. Otherwise we'd shadow the entries written by the actual
        // owning controller.
        let scope = default_scope();
        let r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent("foreign-gw")],
        );
        let parents = build_route_status(&r, &scope, RouteOutcome::NotMine);
        assert!(parents.is_empty());
    }

    #[test]
    fn build_status_skips_parent_refs_we_dont_own() {
        // A route can have multiple parents, only some sōzune-owned.
        // We must produce one entry per owned parent, and zero for the
        // others.
        let scope = default_scope();
        let r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent("foreign-gw"), parent_default_gw()],
        );
        let parents = build_route_status(&r, &scope, RouteOutcome::Accepted);
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].parent_ref.name, "gw");
    }

    #[test]
    fn merge_status_preserves_other_controllers_entries() {
        let foreign = HTTPRouteStatusParents {
            controller_name: "traefik.io/gateway-controller".into(),
            parent_ref: HTTPRouteStatusParentsParentRef {
                name: "their-gw".into(),
                ..Default::default()
            },
            conditions: Some(vec![Condition {
                type_: "Accepted".into(),
                status: "True".into(),
                reason: "Accepted".into(),
                message: "their message".into(),
                last_transition_time: Time(k8s_openapi::chrono::Utc::now()),
                observed_generation: None,
            }]),
        };
        let existing = HTTPRouteStatus {
            parents: vec![foreign.clone()],
        };

        let scope = default_scope();
        let r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent_default_gw()],
        );
        let ours = build_route_status(&r, &scope, RouteOutcome::Accepted);
        let (merged, changed) = merge_route_status(Some(&existing), ours);
        assert!(changed);
        assert_eq!(merged.len(), 2);
        assert!(
            merged
                .iter()
                .any(|p| p.controller_name == "traefik.io/gateway-controller"),
            "Traefik's slice must survive sōzune's status write"
        );
        assert!(
            merged
                .iter()
                .any(|p| p.controller_name == SOZUNE_CONTROLLER_NAME)
        );
    }

    #[test]
    fn merge_status_skips_when_only_timestamp_differs() {
        // Re-resolve runs every 2 seconds; without dedup we'd PATCH the
        // status on every tick (apiserver hammering, audit log noise).
        // Equivalence ignores last_transition_time.
        let scope = default_scope();
        let r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent_default_gw()],
        );
        let first = build_route_status(&r, &scope, RouteOutcome::Accepted);
        // Simulate a status write having already happened: the
        // existing object now contains our slice. A second computation
        // of the same outcome should be detected as a no-op.
        let existing = HTTPRouteStatus {
            parents: first.clone(),
        };
        // Sleep a few ms so timestamps actually differ.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let second = build_route_status(&r, &scope, RouteOutcome::Accepted);
        let (_merged, changed) = merge_route_status(Some(&existing), second);
        assert!(
            !changed,
            "identical outcome must not trigger a status write — only the timestamp changed"
        );
    }

    #[test]
    fn merge_status_replaces_our_slice_when_outcome_flips() {
        let scope = default_scope();
        let r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent_default_gw()],
        );
        let accepted = build_route_status(&r, &scope, RouteOutcome::Accepted);
        let existing = HTTPRouteStatus {
            parents: accepted.clone(),
        };
        let unsupported = build_route_status(&r, &scope, RouteOutcome::UnsupportedFilters);
        let (merged, changed) = merge_route_status(Some(&existing), unsupported);
        assert!(changed);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            condition(&merged, 0, CONDITION_TYPE_ACCEPTED).status,
            "False",
            "our slice should now reflect the new outcome"
        );
    }

    // ---------- Scope tests ----------
    //
    // These exercise the GatewayClass + Gateway matching logic that
    // decides whether a HTTPRoute is sōzune's to serve. Without this,
    // sōzune would hijack routes meant for other Gateway controllers in
    // any cluster running more than one implementation.

    fn class(name: &str, controller: &str) -> GatewayClass {
        GatewayClass {
            metadata: ObjectMeta {
                name: Some(name.into()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: controller.into(),
                ..Default::default()
            },
            status: Default::default(),
        }
    }

    fn gateway(ns: &str, name: &str, class_name: &str) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some(ns.into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: class_name.into(),
                ..Default::default()
            },
            status: Default::default(),
        }
    }

    fn parent(name: &str) -> HTTPRouteParentRefs {
        HTTPRouteParentRefs {
            name: name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn scope_starts_empty_and_rejects_everything() {
        let scope = GatewayScope::new();
        let r = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent("gw")],
        );
        assert!(!scope.accepts_route(&r));
    }

    #[test]
    fn scope_accepts_class_only_when_controller_name_matches() {
        let scope = GatewayScope::new();
        // Wrong controller — Traefik's, say.
        assert!(!scope.upsert_gateway_class(&class("foreign", "traefik.io/gateway-controller")));
        // Sōzune's controller — should be accepted, and the call should
        // signal a change.
        assert!(scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME)));
        // Re-applying an already-accepted class is a no-op.
        assert!(!scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME)));
    }

    #[test]
    fn gateway_accepted_only_when_its_class_is_owned() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));

        // Gateway pointing at a class we don't own — rejected silently.
        assert!(!scope.upsert_gateway(&gateway("default", "gw", "foreign")));
        let r = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent("gw")],
        );
        assert!(!scope.accepts_route(&r));

        // Gateway pointing at our class — accepted, route flips in.
        assert!(scope.upsert_gateway(&gateway("default", "gw", "sozune")));
        assert!(scope.accepts_route(&r));
    }

    #[test]
    fn route_in_other_namespace_must_use_explicit_parent_namespace() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        scope.upsert_gateway(&gateway("infra", "gw", "sozune"));

        // Route in `apps` ns with bare parentRef name `gw` resolves to
        // `apps/gw` — not what's accepted.
        let mut r = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent("gw")],
        );
        r.metadata.namespace = Some("apps".into());
        assert!(!scope.accepts_route(&r));

        // Same route with explicit parent namespace — accepted.
        r.spec.parent_refs = Some(vec![HTTPRouteParentRefs {
            name: "gw".into(),
            namespace: Some("infra".into()),
            ..Default::default()
        }]);
        assert!(scope.accepts_route(&r));
    }

    #[test]
    fn parent_ref_with_non_gateway_kind_is_rejected() {
        let scope = default_scope();
        let r = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![HTTPRouteParentRefs {
                name: "gw".into(),
                kind: Some("Service".into()),
                ..Default::default()
            }],
        );
        assert!(!scope.accepts_route(&r));
    }

    #[test]
    fn parent_ref_with_foreign_group_is_rejected() {
        let scope = default_scope();
        let r = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![HTTPRouteParentRefs {
                name: "gw".into(),
                group: Some("networking.example.io".into()),
                ..Default::default()
            }],
        );
        assert!(!scope.accepts_route(&r));
    }

    #[test]
    fn parent_ref_with_empty_group_is_accepted() {
        // The Gateway API spec treats an empty `group` as the core group
        // for the resource, which for HTTPRoute parents means the
        // standard `gateway.networking.k8s.io` group. Mirror that.
        let scope = default_scope();
        let r = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![HTTPRouteParentRefs {
                name: "gw".into(),
                group: Some(String::new()),
                ..Default::default()
            }],
        );
        assert!(scope.accepts_route(&r));
    }

    #[test]
    fn route_without_parent_refs_is_rejected() {
        let scope = default_scope();
        let r = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![],
        );
        assert!(!scope.accepts_route(&r));
    }

    #[test]
    fn one_matching_parent_among_many_accepts_the_route() {
        let scope = default_scope();
        let r = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![
                HTTPRouteParentRefs {
                    name: "other-controller-gw".into(),
                    ..Default::default()
                },
                parent("gw"),
            ],
        );
        assert!(scope.accepts_route(&r));
    }

    #[test]
    fn changing_class_controller_name_drops_dependent_gateways() {
        // A class flipping from sōzune to another controller must drop
        // every Gateway that pointed at it — otherwise we'd keep serving
        // routes whose owner is no longer ours.
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        scope.upsert_gateway(&gateway("default", "gw", "sozune"));
        let r = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent("gw")],
        );
        assert!(scope.accepts_route(&r));

        // Class re-applied with a foreign controller — accepted set
        // shrinks, route flips out.
        assert!(scope.upsert_gateway_class(&class("sozune", "other.example.io/ctrl")));
        assert!(!scope.accepts_route(&r));
    }

    #[test]
    fn gateway_delete_makes_route_out_of_scope() {
        let scope = default_scope();
        let r = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent("gw")],
        );
        assert!(scope.accepts_route(&r));
        assert!(scope.remove_gateway("default", "gw"));
        assert!(!scope.accepts_route(&r));
        // Removing the same Gateway twice is a no-op (and doesn't notify
        // again).
        assert!(!scope.remove_gateway("default", "gw"));
    }

    #[test]
    fn class_delete_drops_dependent_gateways() {
        let scope = default_scope();
        assert!(scope.remove_gateway_class("sozune"));
        let r = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent("gw")],
        );
        assert!(!scope.accepts_route(&r));
    }

    #[test]
    fn apply_route_out_of_scope_keeps_route_tracked_with_zero_entrypoints() {
        // The watcher must remember out-of-scope routes so they activate
        // the moment a matching Gateway appears — without re-receiving
        // the route from the apiserver.
        let scope = GatewayScope::new();
        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));
        let r = route_with_uid(
            "uid-orphan",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
        );

        // Out of scope (no GatewayClass accepted yet) — no entrypoint.
        let changed = apply_route(&r, &storage, &index, &r1(), &scope, None);
        assert!(!changed, "no storage write the first time around");
        assert!(storage.read().unwrap().is_empty());
        assert_eq!(
            index
                .read()
                .unwrap()
                .get("uid-orphan")
                .unwrap()
                .entrypoint_ids
                .len(),
            0,
            "route is tracked even though it's out of scope"
        );
    }

    #[test]
    fn re_resolve_after_gateway_appears_activates_orphan_route() {
        let scope = GatewayScope::new();
        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));
        let r = route_with_uid(
            "uid-orphan",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
        );

        apply_route(&r, &storage, &index, &r1(), &scope, None);
        assert!(storage.read().unwrap().is_empty());

        // GatewayClass and Gateway show up.
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        scope.upsert_gateway(&gateway("default", "gw", "sozune"));
        // Re-resolve — the orphan flips into scope.
        let changed = re_resolve_all(&storage, &index, &r1(), &scope, None);
        assert!(changed);
        assert_eq!(storage.read().unwrap().len(), 1);
    }

    #[test]
    fn re_resolve_after_gateway_removed_clears_route() {
        let scope = default_scope();
        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));
        let r = route_with_uid(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
        );
        apply_route(&r, &storage, &index, &r1(), &scope, None);
        assert_eq!(storage.read().unwrap().len(), 1);

        scope.remove_gateway("default", "gw");
        let changed = re_resolve_all(&storage, &index, &r1(), &scope, None);
        assert!(changed);
        assert!(storage.read().unwrap().is_empty());
        // Index keeps the route so a later Gateway recreation revives
        // it.
        assert!(index.read().unwrap().contains_key("uid-1"));
    }

    #[tokio::test]
    async fn scope_changes_notify_subscribers() {
        // The HTTPRoute watcher subscribes to `scope.changed()` so it
        // can re-resolve immediately. Verify the notify wiring fires on
        // mutations and stays quiet when nothing changed.
        let scope = GatewayScope::new();
        let waiter = {
            let scope = scope.clone();
            tokio::spawn(async move { scope.changed().await })
        };

        // A real change — should wake the waiter within the timeout.
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        tokio::time::timeout(std::time::Duration::from_millis(200), waiter)
            .await
            .expect("scope.changed() should fire on a real mutation")
            .expect("subscriber task panicked");
    }

    #[tokio::test]
    async fn no_op_upsert_does_not_notify() {
        // Re-applying the same accepted GatewayClass twice must not
        // wake a subscriber — we'd thrash the HTTPRoute re-resolve loop
        // on every relist otherwise.
        //
        // `tokio::sync::Notify::notify_one` posts a permit that the next
        // `notified().await` consumes, so we need a clean baseline
        // (subscribe + drain the first notification) before testing the
        // no-op path.
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        // Drain the permit posted by the first (real) change.
        scope.changed().await;

        // Now subscribe and trigger a no-op apply; the subscriber must
        // never resolve.
        let waiter = {
            let scope = scope.clone();
            tokio::spawn(async move { scope.changed().await })
        };
        // Yield once so the spawned task actually parks on `notified()`
        // before we mutate the scope.
        tokio::task::yield_now().await;

        let again = scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        assert!(!again, "no-op upsert returns false");

        let timed_out = tokio::time::timeout(std::time::Duration::from_millis(50), waiter)
            .await
            .is_err();
        assert!(
            timed_out,
            "no-op upsert must not wake `scope.changed()` subscribers"
        );
    }
}
