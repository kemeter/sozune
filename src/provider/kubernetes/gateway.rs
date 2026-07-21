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

use super::gateway_filters;
use super::gateway_matches;
use crate::model::{
    Backend, Entrypoint, EntrypointConfig, LoadBalancer, PathConfig, PathRuleType, Protocol,
};
use futures_util::StreamExt;
use gateway_api::apis::experimental::tcproutes::{TCPRoute, TCPRouteParentRefs, TCPRouteRules};
use gateway_api::apis::experimental::tlsroutes::{TLSRoute, TLSRouteParentRefs, TLSRouteRules};
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::{Gateway, GatewayListenersTlsMode};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HTTPRouteParentRefs, HTTPRouteRules, HTTPRouteRulesMatches,
    HTTPRouteRulesMatchesPathType, HTTPRouteStatus, HTTPRouteStatusParents,
    HTTPRouteStatusParentsParentRef,
};
use gateway_api::apis::standard::referencegrants::ReferenceGrant;
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

/// Route watchers that consume `GatewayScope::changed()`: HTTPRoute, TLSRoute
/// and TCPRoute. Each scope mutation posts one permit per watcher so all
/// re-resolve immediately instead of one waiting out its periodic tick.
/// Bump this when adding another route watcher.
const SCOPE_SUBSCRIBERS: usize = 3;

/// In-memory snapshot of the Gateway API resources sōzune has decided to
/// honour. The HTTPRoute watcher consults this on every apply to decide
/// whether a route is in scope; the GatewayClass and Gateway watchers
/// mutate it.
///
/// Keeping it as an explicit struct (rather than two free-standing
/// `RwLock`s) lets us atomically answer "is this route in scope?" in
/// constant time without partial views during concurrent updates.
/// The slice of a Gateway `spec.listeners[]` entry sōzune needs to bind a
/// route to a specific listener. Protocol/TLS/port-binding are out of scope
/// (HTTP serving stays on the configured listener); what matters here is
/// resolving a `parentRef`'s `sectionName`/`port` to a listener and
/// intersecting the listener `hostname` with the route's hostnames.
// No `Eq`: the upstream `GatewayListenersTlsMode` only derives `PartialEq`.
#[derive(Clone, Debug, PartialEq)]
pub struct ListenerInfo {
    /// Listener `name`, unique within the Gateway. Matched against a
    /// `parentRef.sectionName`.
    pub name: String,
    /// Listener `port`. Matched against a `parentRef.port`.
    pub port: i32,
    /// Optional listener `hostname`. When set, a route attached to this
    /// listener only serves hostnames that match it.
    pub hostname: Option<String>,
    /// Listener `protocol`, verbatim (`HTTP`, `HTTPS`, `TLS`, `TCP`, `UDP`).
    /// HTTP serving ignores it — an HTTPRoute is served on the configured
    /// listener whatever this says — but a TLSRoute only attaches to a `TLS`
    /// listener, so the shape has to be visible here.
    pub protocol: String,
    /// `tls.mode` when the listener declares one. A TLSRoute requires
    /// `Passthrough`: under `Terminate` the Gateway would decrypt, which is a
    /// different feature (and one Sōzune serves through HTTPS entrypoints).
    pub tls_mode: Option<GatewayListenersTlsMode>,
}

/// The parts of a `parentRef` scope resolution actually reads. HTTPRoute and
/// TLSRoute each get their own generated `…ParentRefs` struct with identical
/// fields, so the acceptance rules are shared through this rather than
/// duplicated per route kind.
pub trait ParentRef {
    fn group(&self) -> Option<&str>;
    fn kind(&self) -> Option<&str>;
    fn name(&self) -> &str;
    fn namespace(&self) -> Option<&str>;
    fn section_name(&self) -> Option<&str>;
    fn port(&self) -> Option<i32>;
}

macro_rules! impl_parent_ref {
    ($t:ty) => {
        impl ParentRef for $t {
            fn group(&self) -> Option<&str> {
                self.group.as_deref()
            }
            fn kind(&self) -> Option<&str> {
                self.kind.as_deref()
            }
            fn name(&self) -> &str {
                &self.name
            }
            fn namespace(&self) -> Option<&str> {
                self.namespace.as_deref()
            }
            fn section_name(&self) -> Option<&str> {
                self.section_name.as_deref()
            }
            fn port(&self) -> Option<i32> {
                self.port
            }
        }
    };
}

impl_parent_ref!(HTTPRouteParentRefs);
impl_parent_ref!(TLSRouteParentRefs);
impl_parent_ref!(TCPRouteParentRefs);

#[derive(Default, Debug)]
pub struct ScopeState {
    /// Names of GatewayClasses whose `spec.controllerName` matches
    /// [`SOZUNE_CONTROLLER_NAME`]. Cluster-scoped, so a flat set is
    /// enough.
    gateway_classes: HashSet<String>,
    /// Gateways we accept, keyed by `(namespace, name)`, mapping to the
    /// listeners each one declares. A Gateway is accepted iff
    /// `spec.gatewayClassName` is in `gateway_classes`. The listener list
    /// lets a route's `parentRef` bind to a specific listener via
    /// `sectionName`/`port`, and lets a listener's `hostname` narrow which
    /// route hostnames it serves.
    gateways: HashMap<(String, String), Vec<ListenerInfo>>,
    /// Cross-namespace backendRef authorisations, keyed by
    /// `(from_namespace, to_namespace)`: the namespace of the referencing
    /// HTTPRoute and the namespace of the referenced Service. A pair is
    /// present iff a `ReferenceGrant` in `to_namespace` permits an
    /// `HTTPRoute` from `from_namespace` to reach a `Service`. Same-namespace
    /// refs never need a grant and are not stored here.
    reference_grants: HashSet<(String, String)>,
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
    ///
    /// When the `parentRef` names a specific listener — via `sectionName`
    /// (matched against a listener `name`) or `port` — the Gateway must
    /// have a listener that matches, otherwise the ref is refused. Per
    /// spec, an unset `sectionName`/`port` binds to the whole Gateway (any
    /// listener), which is the existing behaviour.
    fn accepts_parent_ref<P: ParentRef>(&self, route_namespace: &str, parent_ref: &P) -> bool {
        // No predicate: an HTTPRoute is served on the configured HTTP listener
        // whatever the Gateway declares — including when it declares nothing.
        self.accepts_parent_ref_where(
            route_namespace,
            parent_ref,
            None::<fn(&ListenerInfo) -> bool>,
        )
    }

    /// `accepts_parent_ref`, optionally narrowed to listeners satisfying
    /// `listener_ok`. TLSRoute passes a predicate to require a
    /// `TLS`/`Passthrough` listener; HTTPRoute passes `None`.
    ///
    /// The distinction matters for a Gateway declaring no listeners: per spec
    /// it is still selected by a ref naming neither `sectionName` nor `port`,
    /// which `None` preserves. A predicate instead demands that at least one
    /// listener survive it — a TLSRoute with nowhere to attach cannot be
    /// served, so accepting it would strand the route.
    fn accepts_parent_ref_where<P: ParentRef>(
        &self,
        route_namespace: &str,
        parent_ref: &P,
        listener_ok: Option<impl Fn(&ListenerInfo) -> bool>,
    ) -> bool {
        let kind = parent_ref.kind().unwrap_or("Gateway");
        if kind != "Gateway" {
            return false;
        }
        let group = parent_ref.group().unwrap_or(GATEWAY_API_GROUP);
        // Empty string is a deliberate signal in the API ("core group");
        // we accept it the same way kubectl does for HTTPRoute parents.
        if !group.is_empty() && group != GATEWAY_API_GROUP {
            return false;
        }
        let ns = parent_ref.namespace().unwrap_or(route_namespace);
        let key = (ns.to_string(), parent_ref.name().to_string());
        match self.state.read() {
            Ok(g) => match g.gateways.get(&key) {
                Some(listeners) => match &listener_ok {
                    None => parent_ref_selects_listener(parent_ref, listeners),
                    Some(pred) => {
                        let eligible: Vec<ListenerInfo> =
                            listeners.iter().filter(|l| pred(l)).cloned().collect();
                        !eligible.is_empty() && parent_ref_selects_listener(parent_ref, &eligible)
                    }
                },
                None => false,
            },
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                false
            }
        }
    }

    /// True iff this listener can carry a TLSRoute: protocol `TLS` with
    /// `tls.mode: Passthrough`. `Terminate` is deliberately excluded — the
    /// Gateway would decrypt, which is what HTTPS entrypoints are for.
    fn listener_serves_tls_passthrough(l: &ListenerInfo) -> bool {
        l.protocol.eq_ignore_ascii_case("TLS")
            && matches!(l.tls_mode, Some(GatewayListenersTlsMode::Passthrough))
    }

    /// True iff `parent_ref` binds this TLSRoute to a `TLS`/`Passthrough`
    /// listener on a Gateway we own.
    fn accepts_tls_parent_ref(
        &self,
        route_namespace: &str,
        parent_ref: &TLSRouteParentRefs,
    ) -> bool {
        self.accepts_parent_ref_where(
            route_namespace,
            parent_ref,
            Some(Self::listener_serves_tls_passthrough),
        )
    }

    /// True iff at least one `parentRef` binds this TLSRoute to a listener we
    /// can serve.
    pub fn accepts_tls_route(&self, route: &TLSRoute) -> bool {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let Some(refs) = route.spec.parent_refs.as_ref() else {
            return false;
        };
        refs.iter()
            .any(|p| self.accepts_tls_parent_ref(route_ns, p))
    }

    /// True iff this listener can carry a TCPRoute: protocol `TCP`. Raw TCP has
    /// no TLS to reason about, so unlike a TLSRoute listener there is no `mode`
    /// to check.
    fn listener_serves_tcp(l: &ListenerInfo) -> bool {
        l.protocol.eq_ignore_ascii_case("TCP")
    }

    /// True iff `parent_ref` binds this TCPRoute to a `TCP` listener we own.
    fn accepts_tcp_parent_ref(
        &self,
        route_namespace: &str,
        parent_ref: &TCPRouteParentRefs,
    ) -> bool {
        self.accepts_parent_ref_where(route_namespace, parent_ref, Some(Self::listener_serves_tcp))
    }

    /// True iff at least one `parentRef` binds this TCPRoute to a listener we
    /// can serve.
    pub fn accepts_tcp_route(&self, route: &TCPRoute) -> bool {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let Some(refs) = route.spec.parent_refs.as_ref() else {
            return false;
        };
        refs.iter()
            .any(|p| self.accepts_tcp_parent_ref(route_ns, p))
    }

    /// The Gateway listener ports this TCPRoute binds to. Unlike a TLSRoute
    /// there are no hostnames to intersect — raw TCP forwards the whole port —
    /// so this yields just the set of ports, resolved to `proxy.tcp` listeners
    /// by the caller. A route may bind several listeners on different ports;
    /// each gets its own entrypoint.
    fn effective_tcp_ports(&self, route: &TCPRoute) -> std::collections::BTreeSet<i32> {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let mut ports = std::collections::BTreeSet::new();
        let Some(refs) = route.spec.parent_refs.as_ref() else {
            return ports;
        };
        for p in refs
            .iter()
            .filter(|p| self.accepts_tcp_parent_ref(route_ns, p))
        {
            let ns = p.namespace.as_deref().unwrap_or(route_ns);
            let Some(listeners) = self.gateway_listeners(ns, &p.name) else {
                continue;
            };
            for listener in listeners.into_iter().filter(Self::listener_serves_tcp) {
                // Honour a parentRef that pins a sectionName/port, exactly as
                // the TLS path does.
                let name_ok = p.section_name.as_deref().is_none_or(|s| s == listener.name);
                let port_ok = p.port.is_none_or(|port| port == listener.port);
                if name_ok && port_ok {
                    ports.insert(listener.port);
                }
            }
        }
        ports
    }

    /// The SNI names this TLSRoute should serve, and the Gateway listener port
    /// they arrive on.
    ///
    /// Mirrors [`Self::effective_hostnames_for_route`] but over TLS listeners,
    /// and additionally reports the port: unlike HTTP — where every route is
    /// served on the one configured listener — a passthrough route needs a real
    /// TCP listener, resolved from that port by the caller.
    ///
    /// `None` when the route binds to nothing we own, or when the intersection
    /// with every bound listener's hostname is empty. A route with no
    /// hostnames of its own inherits the listener's; if neither names anything,
    /// there is no SNI to match on and the route is refused rather than
    /// silently serving nothing.
    fn effective_tls_hostnames_by_port(&self, route: &TLSRoute) -> BTreeMap<i32, Vec<String>> {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let route_hostnames = route.spec.hostnames.clone().unwrap_or_default();
        let mut by_port: BTreeMap<i32, Vec<String>> = BTreeMap::new();
        let Some(refs) = route.spec.parent_refs.as_ref() else {
            return by_port;
        };

        for p in refs
            .iter()
            .filter(|p| self.accepts_tls_parent_ref(route_ns, p))
        {
            let ns = p.namespace.as_deref().unwrap_or(route_ns);
            let Some(listeners) = self.gateway_listeners(ns, &p.name) else {
                continue;
            };
            for listener in listeners
                .into_iter()
                .filter(Self::listener_serves_tls_passthrough)
                .filter(|l| {
                    let name_ok = p.section_name.as_deref().is_none_or(|s| s == l.name);
                    let port_ok = p.port.is_none_or(|port| port == l.port);
                    name_ok && port_ok
                })
            {
                // Intersect per listener, not across all of them: a name is
                // only served on a listener whose own hostname admits it.
                // Unioning first and picking one port would expose a name on a
                // listener that refused it, and strand it on the one that
                // wanted it.
                let port = listener.port;
                let Some(hs) =
                    intersect_hostnames(&route_hostnames, std::slice::from_ref(&listener))
                else {
                    continue;
                };
                let entry = by_port.entry(port).or_default();
                for h in hs {
                    if !entry.contains(&h) {
                        entry.push(h);
                    }
                }
            }
        }

        by_port.retain(|_, hs| !hs.is_empty());
        by_port
    }

    /// Returns the listeners of an accepted Gateway named by `(ns, name)`,
    /// or `None` if sōzune doesn't own it. Used to intersect a listener's
    /// `hostname` with a route's hostnames.
    fn gateway_listeners(&self, ns: &str, name: &str) -> Option<Vec<ListenerInfo>> {
        match self.state.read() {
            Ok(g) => g.gateways.get(&(ns.to_string(), name.to_string())).cloned(),
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                None
            }
        }
    }

    /// The hostnames a route's entrypoints should serve, after narrowing
    /// the route's declared hostnames by each bound listener's `hostname`.
    /// Unions the per-parentRef intersections: a route attached to two
    /// listeners serves the union of what each listener admits.
    ///
    /// Returns `Some(hostnames)` (deduplicated, order-stable; an empty vec
    /// means "all hosts", exactly like an empty `spec.hostnames`), or `None`
    /// when every bound listener constrains hostnames and none of them
    /// overlaps the route — the route resolves to nothing on this Gateway.
    /// Falls back to the route's own hostnames when no bound listener
    /// constrains hostnames.
    fn effective_hostnames_for_route(&self, route: &HTTPRoute) -> Option<Vec<String>> {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let route_hostnames = route.spec.hostnames.clone().unwrap_or_default();
        let Some(refs) = route.spec.parent_refs.as_ref() else {
            return Some(route_hostnames);
        };

        let mut out: Vec<String> = Vec::new();
        let mut any_listener = false;
        let mut any_overlap = false;
        for p in refs
            .iter()
            .filter(|p| self.accepts_parent_ref(route_ns, *p))
        {
            let ns = p.namespace.as_deref().unwrap_or(route_ns);
            let Some(listeners) = self.gateway_listeners(ns, &p.name) else {
                continue;
            };
            // Restrict to the listener(s) this parentRef selects, so a
            // sectionName/port ref only inherits its own listener's hostname.
            let selected: Vec<ListenerInfo> = if p.section_name.is_none() && p.port.is_none() {
                listeners
            } else {
                listeners
                    .into_iter()
                    .filter(|l| {
                        let name_ok = p.section_name.as_deref().is_none_or(|s| s == l.name);
                        let port_ok = p.port.is_none_or(|port| port == l.port);
                        name_ok && port_ok
                    })
                    .collect()
            };
            any_listener = true;
            if let Some(hs) = intersect_hostnames(&route_hostnames, &selected) {
                any_overlap = true;
                for h in hs {
                    if !out.contains(&h) {
                        out.push(h);
                    }
                }
            }
        }

        if !any_listener {
            Some(route_hostnames)
        } else if any_overlap {
            Some(out)
        } else {
            None
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
    ///
    /// One `notify_one` per route watcher, not one overall: a single permit is
    /// consumed by whichever watcher wakes first, leaving the other to wait out
    /// its 2s tick before it learns the scope moved. `notify_waiters` would not
    /// do either — it posts no permit, so a watcher not yet parked on
    /// `notified()` misses the change entirely.
    fn fire_if(&self, changed: bool) -> bool {
        if changed {
            for _ in 0..SCOPE_SUBSCRIBERS {
                self.changed.notify_one();
            }
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

    /// Mutates the scope on a Gateway apply. Returns true iff the accepted
    /// set changed — either the Gateway flipped in/out of scope, or (while
    /// accepted) its listener set changed, since a route's binding depends
    /// on the listeners.
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
        let listeners = listeners_of(gateway);

        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return false;
            }
        };
        let key = (ns, name.to_string());
        let accepted = g.gateway_classes.contains(class);
        let changed = match (accepted, g.gateways.get(&key)) {
            (true, None) => {
                g.gateways.insert(key, listeners);
                true
            }
            (true, Some(existing)) if *existing != listeners => {
                g.gateways.insert(key, listeners);
                true
            }
            (true, Some(_)) => false,
            (false, Some(_)) => {
                g.gateways.remove(&key);
                true
            }
            (false, None) => false,
        };
        drop(g);
        self.fire_if(changed)
    }

    /// True iff a Gateway with this `spec.gatewayClassName` would be
    /// accepted, i.e. its class is one sōzune owns. Used by the Gateway
    /// watcher to decide the `Accepted`/`Programmed` status it writes back,
    /// independently of whether the accepted *set* changed on this event.
    pub fn owns_gateway_class(&self, class_name: &str) -> bool {
        match self.state.read() {
            Ok(g) => g.gateway_classes.contains(class_name),
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                false
            }
        }
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
            .remove(&(namespace.to_string(), name.to_string()))
            .is_some();
        drop(g);
        self.fire_if(removed)
    }

    /// True iff an HTTPRoute in `from_ns` may reference a `Service` in
    /// `to_ns`. Same-namespace references are always allowed and never
    /// consult the grant set. A cross-namespace reference is allowed only
    /// when a `ReferenceGrant` in `to_ns` trusts `from_ns` — without one it
    /// is refused, per the Gateway API spec (a namespace must opt in to
    /// being referenced).
    pub fn allows_backend_ref(&self, from_ns: &str, to_ns: &str) -> bool {
        // Grants are keyed by `(from_ns, to_ns)`, not by route kind, so a grant
        // authorising e.g. HTTPRoute→Service also lets a TLSRoute/TCPRoute in
        // the same namespace reach that target. This is slightly more permissive
        // than the spec (a grant names one `from.kind`); tightening it to a
        // per-kind key is a separate hardening step.
        if from_ns == to_ns {
            return true;
        }
        match self.state.read() {
            Ok(g) => g
                .reference_grants
                .contains(&(from_ns.to_string(), to_ns.to_string())),
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                // Fail closed: a poisoned lock must not widen access.
                false
            }
        }
    }

    /// Mutates the scope on a ReferenceGrant apply. The grant lives in the
    /// referenced (`to`) namespace and lists the `from` namespaces/kinds it
    /// trusts. We only care about grants that let an `HTTPRoute` reach a
    /// `Service`; every such `from.namespace` is authorised to reference
    /// this grant's namespace. Returns true iff the authorised set changed.
    pub fn upsert_reference_grant(&self, grant: &ReferenceGrant) -> bool {
        let Some(to_ns) = grant.metadata.namespace.as_deref() else {
            return false;
        };
        let froms = trusted_route_from_namespaces(grant);

        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return false;
            }
        };
        // Recompute this grant's contribution from scratch: drop every pair
        // targeting `to_ns` that this grant could have added, then re-insert
        // the current `from` set. A single grant per (from,to) pair is the
        // common case; on the rare overlap of two grants trusting the same
        // pair, a delete of one still leaves the pair authorised only if the
        // survivor re-adds it — which it does on its own next apply/relist.
        let before: HashSet<(String, String)> = g
            .reference_grants
            .iter()
            .filter(|(_, t)| t == to_ns)
            .cloned()
            .collect();
        let after: HashSet<(String, String)> = froms
            .iter()
            .map(|f| (f.clone(), to_ns.to_string()))
            .collect();
        if before == after {
            return false;
        }
        for pair in &before {
            g.reference_grants.remove(pair);
        }
        for pair in after {
            g.reference_grants.insert(pair);
        }
        drop(g);
        self.fire_if(true)
    }

    /// Mutates the scope on a ReferenceGrant delete: drop every authorised
    /// pair this grant contributed (all pairs targeting its namespace and
    /// listing one of its trusted `from` namespaces).
    pub fn remove_reference_grant(&self, grant: &ReferenceGrant) -> bool {
        let Some(to_ns) = grant.metadata.namespace.as_deref() else {
            return false;
        };
        let froms = trusted_route_from_namespaces(grant);
        if froms.is_empty() {
            return false;
        }

        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return false;
            }
        };
        let mut changed = false;
        for f in froms {
            changed |= g.reference_grants.remove(&(f, to_ns.to_string()));
        }
        drop(g);
        self.fire_if(changed)
    }
}

/// Extract the namespaces of `HTTPRoute` `from` entries in a ReferenceGrant
/// that grants access `to` a `Service`. Only these (route → service)
/// grants are relevant to backendRef resolution; grants for other
/// kind pairs (e.g. Secret references) are ignored.
/// Decides whether a cross-namespace backendRef is authorised. Abstracted
/// behind a trait so `route_to_entrypoints` stays testable without a live
/// [`GatewayScope`]: production passes the scope (grant-aware), tests can
/// pass a stub.
pub trait BackendRefAuthorizer {
    /// True iff an HTTPRoute in `from_ns` may reference a Service in `to_ns`.
    fn allows(&self, from_ns: &str, to_ns: &str) -> bool;
}

impl BackendRefAuthorizer for GatewayScope {
    fn allows(&self, from_ns: &str, to_ns: &str) -> bool {
        self.allows_backend_ref(from_ns, to_ns)
    }
}

/// A [`BackendRefAuthorizer`] that permits every cross-namespace reference.
/// Same-namespace refs never consult an authorizer, so this only matters
/// for the cross-namespace paths in tests that predate grant enforcement.
#[cfg(test)]
pub struct AllowAllBackendRefs;

#[cfg(test)]
impl BackendRefAuthorizer for AllowAllBackendRefs {
    fn allows(&self, _from_ns: &str, _to_ns: &str) -> bool {
        true
    }
}

fn trusted_route_from_namespaces(grant: &ReferenceGrant) -> HashSet<String> {
    let grants_to_service = grant.spec.to.iter().any(|t| {
        let group_ok = t.group.is_empty();
        let kind_ok = t.kind == "Service";
        group_ok && kind_ok
    });
    if !grants_to_service {
        return HashSet::new();
    }
    // A ReferenceGrant's `from` names the route kind it authorises. Recognise
    // every route kind Sōzune serves, not just HTTPRoute — otherwise a
    // TLSRoute or TCPRoute could never reach a cross-namespace backend even
    // with a valid grant in place.
    grant
        .spec
        .from
        .iter()
        .filter(|f| {
            f.group == GATEWAY_API_GROUP
                && matches!(f.kind.as_str(), "HTTPRoute" | "TLSRoute" | "TCPRoute")
        })
        .map(|f| f.namespace.clone())
        .collect()
}

/// Extract the [`ListenerInfo`] slice sōzune tracks from a Gateway's
/// `spec.listeners[]`. Only `name`, `port` and `hostname` are kept — the
/// data needed for `parentRef` listener selection and hostname narrowing.
fn listeners_of(gateway: &Gateway) -> Vec<ListenerInfo> {
    gateway
        .spec
        .listeners
        .iter()
        .map(|l| ListenerInfo {
            name: l.name.clone(),
            port: l.port,
            hostname: l.hostname.clone(),
            protocol: l.protocol.clone(),
            tls_mode: l.tls.as_ref().and_then(|t| t.mode.clone()),
        })
        .collect()
}

/// True iff a `parentRef` selects at least one of `listeners`. An unset
/// `sectionName` and unset `port` bind to the whole Gateway (every
/// listener). When `sectionName` is set it must equal a listener `name`;
/// when `port` is set it must equal a listener `port`; when both are set
/// the same listener must satisfy both. A Gateway with no listeners at all
/// is only selected by a ref that names neither.
fn parent_ref_selects_listener<P: ParentRef>(parent_ref: &P, listeners: &[ListenerInfo]) -> bool {
    let section = parent_ref.section_name();
    let port = parent_ref.port();
    if section.is_none() && port.is_none() {
        return true;
    }
    listeners.iter().any(|l| {
        let name_ok = section.is_none_or(|s| s == l.name);
        let port_ok = port.is_none_or(|p| p == l.port);
        name_ok && port_ok
    })
}

/// Intersect a route's `hostnames` with the listener hostnames it binds to.
/// Per the Gateway API spec, a listener with a `hostname` only serves route
/// hostnames that match it (exact or a shared suffix for wildcard forms);
/// a listener with no `hostname` serves them all. A route with no
/// hostnames inherits the listener hostnames. Returns the effective
/// hostname set the entrypoints should use, or `None` when the
/// intersection is empty (the route doesn't apply to this listener).
fn intersect_hostnames(
    route_hostnames: &[String],
    listeners: &[ListenerInfo],
) -> Option<Vec<String>> {
    let listener_hosts: Vec<&str> = listeners
        .iter()
        .filter_map(|l| l.hostname.as_deref())
        .collect();
    // No listener constrains hostnames → route hostnames pass through
    // unchanged (including an empty list, meaning "all hosts").
    if listener_hosts.len() != listeners.len() || listeners.is_empty() {
        return Some(route_hostnames.to_vec());
    }
    // Every listener has a hostname. A route with no hostnames inherits them.
    if route_hostnames.is_empty() {
        return Some(listener_hosts.iter().map(|h| h.to_string()).collect());
    }
    // Keep each route hostname that matches at least one listener hostname.
    let kept: Vec<String> = route_hostnames
        .iter()
        .filter(|rh| listener_hosts.iter().any(|lh| hostnames_compatible(rh, lh)))
        .cloned()
        .collect();
    if kept.is_empty() { None } else { Some(kept) }
}

/// Two Gateway API hostnames are compatible if one matches the other,
/// honouring a single leading `*.` wildcard on either side (e.g.
/// `*.example.com` matches `api.example.com`). No wildcard → exact match.
fn hostnames_compatible(a: &str, b: &str) -> bool {
    fn matches(pattern: &str, host: &str) -> bool {
        match pattern.strip_prefix("*.") {
            Some(suffix) => host.strip_suffix(suffix).is_some_and(|p| p.ends_with('.')),
            None => pattern == host,
        }
    }
    a == b || matches(a, b) || matches(b, a)
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
pub async fn run_gatewayclass_watcher(
    client: Client,
    scope: GatewayScope,
    status_tx: mpsc::Sender<StatusWrite>,
) -> anyhow::Result<()> {
    let api: Api<GatewayClass> = Api::all(client.clone());
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
                    // A class flipping into (or out of) scope changes which
                    // Gateways are accepted, but the Gateway watcher won't
                    // see a fresh event for Gateways that already exist and
                    // didn't themselves change. Re-list Gateways here and
                    // re-run them through the scope so a Gateway created
                    // before its class was accepted activates immediately
                    // — otherwise its routes stay dark until the Gateway is
                    // next edited. Best-effort: a list failure just defers
                    // the fix to the next event.
                    reconcile_gateways_for_class(&client, &scope, &status_tx).await;
                }
                // Report Accepted status only on classes we own; a class
                // pointing at another controller is not ours to annotate.
                if accepted {
                    queue_status_write(
                        Some(&status_tx),
                        StatusWrite::GatewayClass(Box::new(class.clone())),
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

/// Re-list every Gateway and re-run it through the scope. Called after a
/// GatewayClass acceptance changes, so Gateways that already existed
/// before their class came into scope get re-evaluated (and their status
/// re-written) without waiting for an unrelated edit to trigger a fresh
/// Gateway event. Best-effort: a list failure is logged and dropped.
async fn reconcile_gateways_for_class(
    client: &Client,
    scope: &GatewayScope,
    status_tx: &mpsc::Sender<StatusWrite>,
) {
    let api: Api<Gateway> = Api::all(client.clone());
    let list = match api.list(&Default::default()).await {
        Ok(l) => l,
        Err(e) => {
            warn!("Gateway API: failed to re-list Gateways after class change: {e}");
            return;
        }
    };
    for gw in list {
        let ns = gw.metadata.namespace.as_deref().unwrap_or("<no-namespace>");
        let name = gw.metadata.name.as_deref().unwrap_or("<no-name>");
        if scope.upsert_gateway(&gw) {
            info!(
                "Gateway API: Gateway {}/{} re-evaluated after class change (gatewayClassName={})",
                ns, name, gw.spec.gateway_class_name
            );
        }
        if scope.owns_gateway_class(&gw.spec.gateway_class_name) {
            queue_status_write(Some(status_tx), StatusWrite::Gateway(Box::new(gw)));
        }
    }
}

/// Watch ReferenceGrants cluster-wide and keep the cross-namespace
/// backendRef authorisations in [`GatewayScope`] in sync. A grant lives in
/// the referenced namespace and lists the namespaces/kinds it trusts;
/// mutating the authorised set notifies the HTTPRoute watcher (via the
/// shared `changed` notifier) so a grant appearing or disappearing
/// re-resolves affected routes immediately instead of waiting for the
/// periodic tick.
///
/// On stream errors we log and let the driver reconnect; the relist on
/// reconnect rebuilds the authorised set correctly.
pub async fn run_referencegrant_watcher(client: Client, scope: GatewayScope) -> anyhow::Result<()> {
    let api: Api<ReferenceGrant> = Api::all(client);
    let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();
    info!("Gateway API: ReferenceGrant watcher started");

    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::Apply(grant)) | Ok(Event::InitApply(grant)) => {
                let name = grant.metadata.name.as_deref().unwrap_or("<no-name>");
                let ns = grant
                    .metadata
                    .namespace
                    .as_deref()
                    .unwrap_or("<no-namespace>");
                if scope.upsert_reference_grant(&grant) {
                    info!("Gateway API: ReferenceGrant {}/{} applied", ns, name);
                }
            }
            Ok(Event::Delete(grant)) => {
                let name = grant.metadata.name.as_deref().unwrap_or("<no-name>");
                let ns = grant
                    .metadata
                    .namespace
                    .as_deref()
                    .unwrap_or("<no-namespace>");
                if scope.remove_reference_grant(&grant) {
                    info!("Gateway API: ReferenceGrant {}/{} removed", ns, name);
                }
            }
            Ok(Event::Init) => debug!("Gateway API: ReferenceGrant init"),
            Ok(Event::InitDone) => debug!("Gateway API: ReferenceGrant init done"),
            Err(e) => error!("Gateway API: ReferenceGrant watcher error: {}", e),
        }
    }

    warn!("Gateway API: ReferenceGrant watcher stream ended unexpectedly");
    Ok(())
}

/// Watch Gateways cluster-wide and keep [`GatewayScope`] in sync. A
/// Gateway is accepted iff its `spec.gatewayClassName` matches one of the
/// GatewayClasses sōzune already accepted; the scope stitches the two
/// together transparently.
pub async fn run_gateway_watcher(
    client: Client,
    scope: GatewayScope,
    status_tx: mpsc::Sender<StatusWrite>,
) -> anyhow::Result<()> {
    let api: Api<Gateway> = Api::all(client.clone());
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
                // Report Accepted/Programmed on every Gateway whose class
                // we own; a Gateway pointing at another controller's class
                // is left untouched. The status reflects the current
                // ownership decision, not whether the set changed here.
                if scope.owns_gateway_class(&class) {
                    queue_status_write(Some(&status_tx), StatusWrite::Gateway(Box::new(gw)));
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

/// Build the `conditions[]` sōzune owns on a Gateway's status.
///
/// A Gateway is `Accepted=True` once sōzune owns its GatewayClass, and
/// `Programmed=True` once the routing config derived from it is live —
/// which, for sōzune, is the same instant: acceptance and programming are
/// not staged, so both flip together. `observedGeneration` pins each
/// condition to the spec revision it reflects, so a stale status is
/// visible in `kubectl get`.
fn build_gateway_conditions(gateway: &Gateway, accepted: bool) -> Vec<Condition> {
    let now = Time(k8s_openapi::chrono::Utc::now());
    let generation = gateway.metadata.generation;
    let (status, accepted_msg, programmed_msg) = if accepted {
        (
            "True",
            "Gateway accepted by sōzune".to_string(),
            "Gateway configuration is live".to_string(),
        )
    } else {
        (
            "False",
            "Gateway references a GatewayClass sōzune does not own".to_string(),
            "Gateway is not programmed because it was not accepted".to_string(),
        )
    };
    vec![
        Condition {
            type_: CONDITION_TYPE_ACCEPTED.to_string(),
            status: status.to_string(),
            reason: REASON_ACCEPTED.to_string(),
            message: accepted_msg,
            last_transition_time: now.clone(),
            observed_generation: generation,
        },
        Condition {
            type_: CONDITION_TYPE_PROGRAMMED.to_string(),
            status: status.to_string(),
            reason: REASON_PROGRAMMED.to_string(),
            message: programmed_msg,
            last_transition_time: now,
            observed_generation: generation,
        },
    ]
}

/// Build the single `Accepted` condition sōzune owns on a GatewayClass's
/// status. Only ever called for a class sōzune owns (controllerName
/// matches), so the condition is always `Accepted=True`.
fn build_gatewayclass_conditions(class: &GatewayClass) -> Vec<Condition> {
    vec![Condition {
        type_: CONDITION_TYPE_ACCEPTED.to_string(),
        status: "True".to_string(),
        reason: REASON_ACCEPTED.to_string(),
        message: "GatewayClass accepted by sōzune".to_string(),
        last_transition_time: Time(k8s_openapi::chrono::Utc::now()),
        observed_generation: class.metadata.generation,
    }]
}

/// Merge sōzune's conditions into an existing `conditions[]`, keyed by
/// condition `type`. Conditions of a type sōzune sets are replaced; every
/// other type is preserved (a Gateway's status may carry conditions from
/// address allocation or listener programming that another actor owns).
/// Returns the merged list and whether it differs from what was on the
/// object, ignoring `last_transition_time` — that field is regenerated on
/// every call and would otherwise force a write on every event.
fn merge_conditions(
    existing: Option<&[Condition]>,
    ours: Vec<Condition>,
) -> (Vec<Condition>, bool) {
    let existing = existing.unwrap_or_default();
    let our_types: HashSet<&str> = ours.iter().map(|c| c.type_.as_str()).collect();

    let mut merged: Vec<Condition> = existing
        .iter()
        .filter(|c| !our_types.contains(c.type_.as_str()))
        .cloned()
        .collect();
    merged.extend(ours.iter().cloned());

    // Compare only the slice we own: a change to a foreign condition is not
    // ours to react to. For each of our types, find the matching existing
    // condition and compare the meaningful fields.
    let changed = ours
        .iter()
        .any(|our| match existing.iter().find(|c| c.type_ == our.type_) {
            Some(prev) => {
                prev.status != our.status
                    || prev.reason != our.reason
                    || prev.message != our.message
                    || prev.observed_generation != our.observed_generation
            }
            None => true,
        });

    (merged, changed)
}

/// A pending status write, drained off the watcher hot-path by
/// [`run_gateway_status_writer`]. Patching status means a network round-trip
/// to the apiserver; doing it inline in a watcher's event loop would stall
/// the loop (and every Gateway/GatewayClass behind the current one) until
/// the PATCH returns. So watchers only ever `try_send` one of these; the
/// writer task owns the round-trip.
#[derive(Clone, Debug)]
pub enum StatusWrite {
    Gateway(Box<Gateway>),
    GatewayClass(Box<GatewayClass>),
}

/// Drains [`StatusWrite`]s and patches the `status.conditions[]` sōzune owns
/// onto the target resource, preserving conditions owned by other actors and
/// skipping the write when nothing sōzune cares about changed. Non-fatal:
/// failures are logged at `warn` and dropped, mirroring [`run_status_writer`]
/// — routing works without status, and the next event re-attempts the write.
pub async fn run_gateway_status_writer(client: Client, mut rx: mpsc::Receiver<StatusWrite>) {
    info!("Gateway API: Gateway/GatewayClass status writer started");
    while let Some(msg) = rx.recv().await {
        match msg {
            StatusWrite::Gateway(gw) => patch_gateway_status(&client, &gw).await,
            StatusWrite::GatewayClass(class) => patch_gatewayclass_status(&client, &class).await,
        }
    }
    info!("Gateway API: Gateway/GatewayClass status writer stopped");
}

/// Best-effort hand-off of a status write to the writer task. Never blocks
/// the caller: a full or closed channel just drops the write (status is
/// observability, not routing), and the next event re-attempts it.
fn queue_status_write(tx: Option<&mpsc::Sender<StatusWrite>>, msg: StatusWrite) {
    if let Some(tx) = tx
        && let Err(e) = tx.try_send(msg)
    {
        debug!("Gateway API: status channel full or closed: {}", e);
    }
}

/// Patch the `conditions[]` sōzune owns onto a Gateway's status. A Gateway
/// reaches the writer only when sōzune owns its class, so the conditions are
/// always `Accepted=True`/`Programmed=True`.
async fn patch_gateway_status(client: &Client, gateway: &Gateway) {
    let Some(name) = gateway.metadata.name.as_deref() else {
        return;
    };
    let ns = gateway.metadata.namespace.as_deref().unwrap_or("default");
    let ours = build_gateway_conditions(gateway, true);
    let existing = gateway
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_deref());
    let (merged, changed) = merge_conditions(existing, ours);
    if !changed {
        return;
    }
    let patch = serde_json::json!({
        "status": { "conditions": merged }
    });
    let api: Api<Gateway> = Api::namespaced(client.clone(), ns);
    let pp = PatchParams::default();
    if let Err(e) = api.patch_status(name, &pp, &Patch::Merge(&patch)).await {
        warn!(
            "Gateway API: failed to patch status on Gateway {}/{}: {}",
            ns, name, e
        );
    } else {
        debug!("Gateway API: status patched on Gateway {}/{}", ns, name);
    }
}

/// Patch the `Accepted` condition onto a GatewayClass's status. A class
/// reaches the writer only when sōzune owns it (controllerName matches); a
/// class pointing at another controller is never queued, as Gateway API
/// requires.
async fn patch_gatewayclass_status(client: &Client, class: &GatewayClass) {
    let Some(name) = class.metadata.name.as_deref() else {
        return;
    };
    let ours = build_gatewayclass_conditions(class);
    let existing = class.status.as_ref().and_then(|s| s.conditions.as_deref());
    let (merged, changed) = merge_conditions(existing, ours);
    if !changed {
        return;
    }
    let patch = serde_json::json!({
        "status": { "conditions": merged }
    });
    let api: Api<GatewayClass> = Api::all(client.clone());
    let pp = PatchParams::default();
    if let Err(e) = api.patch_status(name, &pp, &Patch::Merge(&patch)).await {
        warn!(
            "Gateway API: failed to patch status on GatewayClass {}: {}",
            name, e
        );
    } else {
        debug!("Gateway API: status patched on GatewayClass {}", name);
    }
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
    // Routes that declare unsupported filters (requestMirror, extensionRef)
    // or the conflicting requestRedirect+urlRewrite pair are also dropped:
    // routing them as if the filter wasn't there would silently rewrite
    // user intent. Worse than refusing the route — better to surface the
    // problem so the user knows to fall back to Ingress annotations until
    // filter support lands. (requestRedirect, requestHeaderModifier,
    // responseHeaderModifier and urlRewrite are honoured.)
    let (outcome, new_entrypoints) = if !scope.accepts_route(route) {
        (RouteOutcome::NotMine, Vec::new())
    } else if route_has_unsupported_filters(route) {
        let ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let name = route.metadata.name.as_deref().unwrap_or("<no-name>");
        warn!(
            "Gateway API: HTTPRoute {}/{} declares filters sōzune cannot represent (requestRedirect — excluding its path-rewrite and 302 forms — requestHeaderModifier, responseHeaderModifier and urlRewrite are supported; requestMirror and extensionRef are not, and requestRedirect cannot be combined with urlRewrite on the same rule) — dropping the route",
            ns, name
        );
        (RouteOutcome::UnsupportedFilters, Vec::new())
    } else if route_has_unsupported_matches(route) {
        let ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let name = route.metadata.name.as_deref().unwrap_or("<no-name>");
        warn!(
            "Gateway API: HTTPRoute {}/{} declares a RegularExpression header/query match sōzune cannot represent (Exact and presence-only header/query matches, and all method matches, are supported) — dropping the route",
            ns, name
        );
        (RouteOutcome::UnsupportedFilters, Vec::new())
    } else {
        // Narrow the route's hostnames by the listener(s) it binds to: a
        // listener with a `hostname` only serves matching route hostnames.
        // `None` means no bound listener admits any of the route's
        // hostnames, so the route produces nothing here.
        match scope.effective_hostnames_for_route(route) {
            Some(effective_hostnames) => {
                let eps = route_to_entrypoints_with_hostnames(
                    route,
                    resolver,
                    scope,
                    &effective_hostnames,
                );
                let outcome = if eps.is_empty() {
                    RouteOutcome::NoResolvableBackends
                } else {
                    RouteOutcome::Accepted
                };
                (outcome, eps)
            }
            None => (RouteOutcome::NoResolvableBackends, Vec::new()),
        }
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

/// Convenience wrapper that serves the route's own `spec.hostnames`. The
/// live path goes through [`route_to_entrypoints_with_hostnames`] with the
/// listener-narrowed hostnames instead; this form (no listener narrowing)
/// is used by the unit tests.
#[cfg(test)]
pub fn route_to_entrypoints(
    route: &HTTPRoute,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
) -> Vec<Entrypoint> {
    let hostnames = route.spec.hostnames.clone().unwrap_or_default();
    route_to_entrypoints_with_hostnames(route, resolver, grants, &hostnames)
}

/// Convert a HTTPRoute into one or more Sozune `Entrypoint`s, serving
/// `hostnames` (the caller passes the hostnames left after intersecting the
/// route with its bound listeners' hostnames — see
/// [`GatewayScope::effective_hostnames_for_route`]; an empty slice means
/// "all hosts" exactly as an empty `spec.hostnames` does). Each rule
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
pub fn route_to_entrypoints_with_hostnames(
    route: &HTTPRoute,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
    hostnames: &[String],
) -> Vec<Entrypoint> {
    let ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let route_name = match route.metadata.name.as_deref() {
        Some(n) => n,
        None => return Vec::new(),
    };

    let Some(rules) = route.spec.rules.as_ref() else {
        return Vec::new();
    };

    rules
        .iter()
        .enumerate()
        .flat_map(|(idx, rule)| {
            rule_to_entrypoints(ns, route_name, idx, hostnames, rule, resolver, grants)
        })
        .collect()
}

/// True iff at least one rule in the route declares filters sōzune
/// can't faithfully execute today (`requestMirror`, `extensionRef`, a
/// `requestRedirect` in an unmappable form, an empty `urlRewrite`, or the
/// conflicting `requestRedirect`+`urlRewrite` pair on one rule).
/// `requestRedirect`, `requestHeaderModifier`, `responseHeaderModifier`
/// and `urlRewrite` are supported. The HTTPRoute watcher uses
/// this as an early reject so the user sees a clear log line and a
/// `ResolvedRefs=False` status condition rather than wrong behaviour.
pub fn route_has_unsupported_filters(route: &HTTPRoute) -> bool {
    route
        .spec
        .rules
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|rule| match rule.filters.as_deref() {
            Some(filters) if !filters.is_empty() => {
                !gateway_filters::rule_filters_supported(filters)
            }
            _ => false,
        })
}

/// True iff any match in the route declares a condition sōzune can't
/// represent — a `type: RegularExpression` header or query match. Treated
/// like an unsupported filter: the route is rejected (logged, and reflected
/// as `ResolvedRefs=False reason=UnsupportedValue`) rather than served with
/// the regex condition silently dropped, which would route more traffic
/// than the author asked for. Exact and presence-only header/query matches,
/// and all method matches, are supported and don't trip this.
pub fn route_has_unsupported_matches(route: &HTTPRoute) -> bool {
    route
        .spec
        .rules
        .as_deref()
        .unwrap_or_default()
        .iter()
        .flat_map(|rule| rule.matches.as_deref().unwrap_or_default())
        .any(gateway_matches::match_has_unsupported_conditions)
}

// Gateway API standard condition types and reasons. Values are the
// strings consumers (kubectl, gateway-api conformance suite) expect —
// don't paraphrase them.
const CONDITION_TYPE_ACCEPTED: &str = "Accepted";
const CONDITION_TYPE_RESOLVED_REFS: &str = "ResolvedRefs";
const CONDITION_TYPE_PROGRAMMED: &str = "Programmed";
const REASON_ACCEPTED: &str = "Accepted";
const REASON_RESOLVED_REFS: &str = "ResolvedRefs";
const REASON_PROGRAMMED: &str = "Programmed";
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
            "Route declares HTTPRoute filters sōzune cannot represent (requestMirror and extensionRef are unsupported, and requestRedirect cannot be combined with urlRewrite on the same rule; requestRedirect — excluding its path-rewrite and 302 forms — requestHeaderModifier, responseHeaderModifier and urlRewrite are supported)".to_string(),
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
        .filter(|p| scope.accepts_parent_ref(route_ns, *p))
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
    grants: &dyn BackendRefAuthorizer,
) -> Vec<Entrypoint> {
    // Gateway API: each entry in `filters` is meant to mutate the
    // request/response before/after it reaches the backend. We honour the
    // ones we can map faithfully: `requestRedirect` → Sōzu's native
    // frontend redirect, `requestHeaderModifier` / `responseHeaderModifier`
    // → Sōzu's native frontend header edits, and `urlRewrite` → Sōzu's
    // native frontend path/host rewrite (transparent, no redirect). A rule
    // carrying any filter we can't represent (requestMirror, extensionRef),
    // or the conflicting requestRedirect+urlRewrite pair, is refused
    // outright: routing it as if the filter weren't there would silently
    // rewrite user intent. The watcher also gates on
    // `route_has_unsupported_filters` to set the route status, but we
    // re-check here so a direct call can't slip an unsupported filter
    // through.
    let (redirect, header_edits, url_rewrite) = match rule.filters.as_deref() {
        Some(filters) if !filters.is_empty() => {
            if !gateway_filters::rule_filters_supported(filters) {
                return Vec::new();
            }
            (
                gateway_filters::redirect_from_filter(filters),
                gateway_filters::header_edits_from_filters(filters),
                gateway_filters::url_rewrite_from_filter(filters),
            )
        }
        _ => (None, Vec::new(), None),
    };

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
            // Cross-namespace backendRefs require a ReferenceGrant in the
            // target namespace trusting this route's namespace. Without one
            // the ref is dropped (not routed), per the Gateway API spec:
            // a namespace must opt in to being referenced. Same-namespace
            // refs are always allowed and never consult the grant set.
            if !grants.allows(namespace, target_ns) {
                warn!(
                    "Gateway API: HTTPRoute {}/{} references Service {}/{} across namespaces with no ReferenceGrant — dropping the backend",
                    namespace, route_name, target_ns, b.name
                );
                return Vec::new();
            }
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

            // Header / query-param / method conditions, ANDed with the path
            // (and with each other) inside this single match. A match with
            // none of them constrains on path alone. Unrepresentable regex
            // header/query matches never reach here — the route is rejected
            // upstream (see `route_has_unsupported_matches`).
            let match_headers = m
                .map(gateway_matches::match_headers_from)
                .unwrap_or_default();
            let match_query = m.map(gateway_matches::match_query_from).unwrap_or_default();
            let methods = m.map(gateway_matches::methods_from).unwrap_or_default();

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
                    redirect: redirect.as_ref().map(|r| r.policy),
                    redirect_scheme: redirect.as_ref().and_then(|r| r.scheme),
                    redirect_template: None,
                    rewrite_host: redirect.as_ref().and_then(|r| r.host.clone()),
                    rewrite_path: redirect.as_ref().and_then(|r| r.path.clone()),
                    rewrite_port: redirect.as_ref().and_then(|r| r.port),
                    rewrite: url_rewrite.clone(),
                    www_authenticate: None,
                    priority: 0,
                    auth: None,
                    forward_auth: None,
                    headers: header_edits.clone(),
                    backend_timeout: None,
                    health_check: None,
                    load_balancer: LoadBalancer::default(),
                    retry: None,
                    circuit_breaker: None,
                    rate_limit: None,
                    in_flight_req: None,
                    sticky_session: false,
                    compress: false,
                    entrypoint: None,
                    sni: None,
                    methods,
                    acme: None,
                    plugins: Vec::new(),
                    plugin_config: std::collections::BTreeMap::new(),
                    error_pages: std::collections::BTreeMap::new(),
                    match_headers,
                    match_query,
                    match_client_ip: Vec::new(),
                    ip_allow_list: Vec::new(),
                },
                source: Some(id),
            }
        })
        .collect()
}

struct TrackedTlsRoute {
    route: TLSRoute,
    entrypoint_ids: Vec<String>,
}

/// Indexed by Kubernetes UID, like [`RouteIndex`].
type TlsRouteIndex = Arc<RwLock<HashMap<String, TrackedTlsRoute>>>;

/// Resolve a TLSRoute to its entrypoints and swap them into storage. Returns
/// true when storage changed. Mirrors [`apply_route`], minus filters and
/// matches (a TLSRoute has neither), plus the listener-port resolution: a
/// route whose Gateway port has no matching `proxy.tcp` listener cannot be
/// served, so it is tracked with zero entrypoints and reported unresolvable.
fn apply_tls_route(
    route: &TLSRoute,
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &TlsRouteIndex,
    resolver: &dyn ServiceResolver,
    scope: &GatewayScope,
    listener_ports: &TcpListenerPorts,
) -> bool {
    let uid = match route.metadata.uid.as_deref() {
        Some(u) => u.to_string(),
        None => {
            warn!("Gateway API: TLSRoute without uid, skipping");
            return false;
        }
    };

    // Out-of-scope routes stay tracked with zero entrypoints so they activate
    // as soon as a matching Gateway appears, and deactivate cleanly when one
    // goes away — same contract as the HTTP path.
    let new_entrypoints = if !scope.accepts_tls_route(route) {
        Vec::new()
    } else {
        // A route can bind listeners on several ports; each gets its own
        // entrypoint set, serving only the names that listener admits.
        scope
            .effective_tls_hostnames_by_port(route)
            .into_iter()
            .flat_map(|(port, hostnames)| match listener_ports.get(&port) {
                Some(listener_name) => {
                    tls_route_to_entrypoints(route, resolver, scope, &hostnames, listener_name, port)
                }
                None => {
                    let ns = route.metadata.namespace.as_deref().unwrap_or("default");
                    let name = route.metadata.name.as_deref().unwrap_or("<no-name>");
                    warn!(
                        "Gateway API: TLSRoute {}/{} binds to a Gateway listener on port {} but no `proxy.tcp` listener is declared there — declare one in config.yaml, Sōzune does not open TCP ports on the fly",
                        ns, name, port
                    );
                    Vec::new()
                }
            })
            .collect()
    };

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
        TrackedTlsRoute {
            route: route.clone(),
            entrypoint_ids: new_ids,
        },
    );

    changed
}

fn delete_tls_route(
    route: &TLSRoute,
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &TlsRouteIndex,
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

/// Re-resolve every tracked TLSRoute. Driven by the same two signals as the
/// HTTP path: a periodic tick (so EndpointSlice churn reaches Sōzu) and a
/// scope change (so routes flip in/out the moment a Gateway appears).
fn re_resolve_all_tls(
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &TlsRouteIndex,
    resolver: &dyn ServiceResolver,
    scope: &GatewayScope,
    listener_ports: &TcpListenerPorts,
) -> bool {
    let tracked: Vec<TLSRoute> = match index.read() {
        Ok(g) => g.values().map(|t| t.route.clone()).collect(),
        Err(e) => {
            error!("Gateway API: index lock poisoned: {}", e);
            return false;
        }
    };

    let mut changed = false;
    for route in &tracked {
        if apply_tls_route(route, storage, index, resolver, scope, listener_ports) {
            changed = true;
        }
    }
    changed
}

/// Watch TLSRoutes and keep their entrypoints in sync.
///
/// TLSRoute is `v1alpha2` and ships in the Gateway API *experimental* bundle,
/// so the CRD is often absent. The watcher probes for it first and exits
/// quietly when missing rather than logging an error on every retry.
pub async fn run_tlsroute_watcher(
    client: Client,
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    reload_tx: mpsc::Sender<()>,
    resolver: Arc<dyn ServiceResolver>,
    scope: GatewayScope,
    listener_ports: TcpListenerPorts,
) -> anyhow::Result<()> {
    let api: Api<TLSRoute> = Api::all(client);
    // Distinguish "CRD absent" from "not allowed to list it": both stop the
    // watcher, but only the first is routine. Reporting a 403 as a missing CRD
    // would send an operator hunting for the wrong thing.
    if let Err(e) = api.list(&Default::default()).await {
        match &e {
            kube::Error::Api(resp) if resp.code == 404 => {
                info!(
                    "Gateway API: TLSRoute CRD not installed, skipping watcher (it ships in the experimental bundle)"
                );
            }
            kube::Error::Api(resp) if resp.code == 403 => {
                warn!(
                    "Gateway API: not allowed to list TLSRoutes, skipping watcher — grant `tlsroutes` (get/list/watch) in the gateway.networking.k8s.io group: {}",
                    resp.message
                );
            }
            other => {
                warn!(
                    "Gateway API: could not probe for TLSRoutes, skipping watcher: {}",
                    other
                );
            }
        }
        return Ok(());
    }

    let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();
    let index: TlsRouteIndex = Arc::new(RwLock::new(HashMap::new()));
    let mut resolve_ticker = tokio::time::interval(std::time::Duration::from_secs(2));
    resolve_ticker.tick().await;

    info!("Gateway API: TLSRoute watcher started");

    loop {
        let changed = tokio::select! {
            event = stream.next() => match event {
                Some(Ok(Event::Apply(route))) | Some(Ok(Event::InitApply(route))) => {
                    log_tls_route("apply", &route);
                    apply_tls_route(&route, &storage, &index, resolver.as_ref(), &scope, &listener_ports)
                }
                Some(Ok(Event::Delete(route))) => {
                    log_tls_route("delete", &route);
                    delete_tls_route(&route, &storage, &index)
                }
                Some(Ok(Event::Init)) => {
                    debug!("Gateway API: TLSRoute init");
                    false
                }
                Some(Ok(Event::InitDone)) => {
                    debug!("Gateway API: TLSRoute init done");
                    false
                }
                Some(Err(e)) => {
                    error!("Gateway API: TLSRoute watcher error: {}", e);
                    false
                }
                None => break,
            },
            _ = resolve_ticker.tick() => {
                re_resolve_all_tls(&storage, &index, resolver.as_ref(), &scope, &listener_ports)
            }
            _ = scope.changed() => {
                debug!("Gateway API: scope changed, re-resolving TLS routes");
                re_resolve_all_tls(&storage, &index, resolver.as_ref(), &scope, &listener_ports)
            }
        };
        if changed && let Err(e) = reload_tx.send(()).await {
            error!("Gateway API: failed to send reload signal: {}", e);
        }
    }

    warn!("Gateway API: TLSRoute watcher stream ended unexpectedly");
    Ok(())
}

fn log_tls_route(action: &str, route: &TLSRoute) {
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
    debug!(
        "Gateway API: TLSRoute {} {}/{} [{}]",
        action, ns, name, hosts
    );
}

// ---------- TCPRoute ----------
//
// A TCPRoute forwards the whole of a listener port to its backends — no SNI, no
// hostnames, no filters. It is the TLSRoute path with the name-routing removed:
// one catch-all TCP entrypoint per (route, port), `sni: None`.

struct TrackedTcpRoute {
    route: TCPRoute,
    entrypoint_ids: Vec<String>,
}

type TcpRouteIndex = Arc<RwLock<HashMap<String, TrackedTcpRoute>>>;

/// Convert a TCPRoute into Sōzune `Entrypoint`s, one catch-all per rule on the
/// resolved listener. `sni` is `None`: raw TCP does not route by name, so the
/// entrypoint takes the whole port — exactly a Docker `sozune.tcp.*` route with
/// no `sni` label.
pub fn tcp_route_to_entrypoints(
    route: &TCPRoute,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
    listener_name: &str,
    port: i32,
) -> Vec<Entrypoint> {
    let namespace = route.metadata.namespace.as_deref().unwrap_or("default");
    let Some(route_name) = route.metadata.name.as_deref() else {
        return Vec::new();
    };

    route
        .spec
        .rules
        .iter()
        .enumerate()
        .filter_map(|(rule_index, rule)| {
            let backends = tcp_rule_backends(rule, namespace, route_name, resolver, grants);
            if backends.is_empty() {
                return None;
            }
            Some(Entrypoint {
                // `/`-joined and port-scoped for the same injectivity reasons as
                // the TLS path (see `tls_route_to_entrypoints`).
                id: format!("{SOURCE_TAG}-tcp/{namespace}/{route_name}/{port}/{rule_index}"),
                name: format!("{route_name}-{port}-{rule_index}"),
                backends,
                protocol: Protocol::Tcp,
                config: EntrypointConfig {
                    // No `sni`: the listener forwards everything to this backend
                    // set, the raw-TCP catch-all.
                    entrypoint: Some(listener_name.to_string()),
                    ..tls_entrypoint_defaults()
                },
                source: Some(format!("{SOURCE_TAG}-tcp/{namespace}/{route_name}")),
            })
        })
        .collect()
}

/// Resolve a TCPRoute rule's `backendRefs` to pod IPs. Same handling as the TLS
/// path (Service-typed, ReferenceGrant-gated cross-namespace, weight honoured);
/// duplicated rather than shared because `TCPRouteRules` and `TLSRouteRules` are
/// distinct generated types.
fn tcp_rule_backends(
    rule: &TCPRouteRules,
    namespace: &str,
    route_name: &str,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
) -> Vec<Backend> {
    let Some(backend_refs) = rule.backend_refs.as_ref() else {
        return Vec::new();
    };
    backend_refs
        .iter()
        .flat_map(|b| {
            let Some(port_i32) = b.port else {
                return Vec::new();
            };
            let Ok(port) = u16::try_from(port_i32) else {
                return Vec::new();
            };
            let kind_ok = b.kind.as_deref().map(|k| k == "Service").unwrap_or(true);
            let group_ok = b.group.as_deref().map(|g| g.is_empty()).unwrap_or(true);
            if !kind_ok || !group_ok {
                return Vec::new();
            }
            let target_ns = b.namespace.as_deref().unwrap_or(namespace);
            if !grants.allows(namespace, target_ns) {
                warn!(
                    "Gateway API: TCPRoute {}/{} references Service {}/{} across namespaces with no ReferenceGrant — dropping the backend",
                    namespace, route_name, target_ns, b.name
                );
                return Vec::new();
            }
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
        .collect()
}

/// Resolve a TCPRoute to its entrypoints and swap them into storage. Mirrors
/// [`apply_tls_route`], minus hostnames.
fn apply_tcp_route(
    route: &TCPRoute,
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &TcpRouteIndex,
    resolver: &dyn ServiceResolver,
    scope: &GatewayScope,
    listener_ports: &TcpListenerPorts,
) -> bool {
    let uid = match route.metadata.uid.as_deref() {
        Some(u) => u.to_string(),
        None => {
            warn!("Gateway API: TCPRoute without uid, skipping");
            return false;
        }
    };

    let new_entrypoints = if !scope.accepts_tcp_route(route) {
        Vec::new()
    } else {
        scope
            .effective_tcp_ports(route)
            .into_iter()
            .flat_map(|port| match listener_ports.get(&port) {
                Some(listener_name) => {
                    tcp_route_to_entrypoints(route, resolver, scope, listener_name, port)
                }
                None => {
                    let ns = route.metadata.namespace.as_deref().unwrap_or("default");
                    let name = route.metadata.name.as_deref().unwrap_or("<no-name>");
                    warn!(
                        "Gateway API: TCPRoute {}/{} binds to a Gateway listener on port {} but no `proxy.tcp` listener is declared there — declare one in config.yaml, Sōzune does not open TCP ports on the fly",
                        ns, name, port
                    );
                    Vec::new()
                }
            })
            .collect()
    };

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
        TrackedTcpRoute {
            route: route.clone(),
            entrypoint_ids: new_ids,
        },
    );

    changed
}

fn delete_tcp_route(
    route: &TCPRoute,
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &TcpRouteIndex,
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

fn re_resolve_all_tcp(
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &TcpRouteIndex,
    resolver: &dyn ServiceResolver,
    scope: &GatewayScope,
    listener_ports: &TcpListenerPorts,
) -> bool {
    let tracked: Vec<TCPRoute> = match index.read() {
        Ok(g) => g.values().map(|t| t.route.clone()).collect(),
        Err(e) => {
            error!("Gateway API: index lock poisoned: {}", e);
            return false;
        }
    };

    let mut changed = false;
    for route in &tracked {
        if apply_tcp_route(route, storage, index, resolver, scope, listener_ports) {
            changed = true;
        }
    }
    changed
}

/// Watch TCPRoutes and keep their entrypoints in sync. `v1alpha2`/experimental
/// like TLSRoute, so the CRD is probed and the watcher exits quietly if absent.
pub async fn run_tcproute_watcher(
    client: Client,
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    reload_tx: mpsc::Sender<()>,
    resolver: Arc<dyn ServiceResolver>,
    scope: GatewayScope,
    listener_ports: TcpListenerPorts,
) -> anyhow::Result<()> {
    let api: Api<TCPRoute> = Api::all(client);
    if api.list(&Default::default()).await.is_err() {
        info!(
            "Gateway API: TCPRoute CRD not installed, skipping watcher (it ships in the experimental bundle)"
        );
        return Ok(());
    }

    let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();
    let index: TcpRouteIndex = Arc::new(RwLock::new(HashMap::new()));
    let mut resolve_ticker = tokio::time::interval(std::time::Duration::from_secs(2));
    resolve_ticker.tick().await;

    info!("Gateway API: TCPRoute watcher started");

    loop {
        let changed = tokio::select! {
            event = stream.next() => match event {
                Some(Ok(Event::Apply(route))) | Some(Ok(Event::InitApply(route))) => {
                    log_tcp_route("apply", &route);
                    apply_tcp_route(&route, &storage, &index, resolver.as_ref(), &scope, &listener_ports)
                }
                Some(Ok(Event::Delete(route))) => {
                    log_tcp_route("delete", &route);
                    delete_tcp_route(&route, &storage, &index)
                }
                Some(Ok(Event::Init)) => {
                    debug!("Gateway API: TCPRoute init");
                    false
                }
                Some(Ok(Event::InitDone)) => {
                    debug!("Gateway API: TCPRoute init done");
                    false
                }
                Some(Err(e)) => {
                    error!("Gateway API: TCPRoute watcher error: {}", e);
                    false
                }
                None => break,
            },
            _ = resolve_ticker.tick() => {
                re_resolve_all_tcp(&storage, &index, resolver.as_ref(), &scope, &listener_ports)
            }
            _ = scope.changed() => {
                debug!("Gateway API: scope changed, re-resolving TCP routes");
                re_resolve_all_tcp(&storage, &index, resolver.as_ref(), &scope, &listener_ports)
            }
        };
        if changed && let Err(e) = reload_tx.send(()).await {
            error!("Gateway API: failed to send reload signal: {}", e);
        }
    }

    warn!("Gateway API: TCPRoute watcher stream ended unexpectedly");
    Ok(())
}

fn log_tcp_route(action: &str, route: &TCPRoute) {
    let ns = route
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("<no-namespace>");
    let name = route.metadata.name.as_deref().unwrap_or("<no-name>");
    debug!("Gateway API: TCPRoute {} {}/{}", action, ns, name);
}

/// Maps a Gateway listener port onto the name of a statically declared
/// `proxy.tcp` listener.
///
/// Sōzune binds TCP ports at startup from `config.yaml` and deliberately does
/// not open them on the fly, so a Gateway declaring `port: 8443` is served only
/// if some `proxy.tcp` entry already listens there. Built once at startup and
/// read on every TLSRoute apply.
pub type TcpListenerPorts = Arc<HashMap<i32, String>>;

/// Build the port → listener-name table from the proxy config.
pub fn tcp_listener_ports(tcp: &[crate::config::TcpListenerConfig]) -> TcpListenerPorts {
    Arc::new(
        tcp.iter()
            .map(|l| (i32::from(l.listen), l.name.clone()))
            .collect(),
    )
}

/// Convert a TLSRoute into Sōzune `Entrypoint`s, one per (rule, hostname).
///
/// Much simpler than its HTTP counterpart: a TLSRoute has no matches, no
/// filters and no paths — the SNI *is* the whole routing decision — so a rule
/// fans out only over `hostnames`. Sōzu keys a TCP frontend on one SNI, so a
/// route serving three names becomes three entrypoints sharing one backend set.
///
/// `hostnames` are the names left after intersecting the route with its bound
/// listeners (see [`GatewayScope::effective_hostnames_for_tls_route`]). Unlike
/// HTTP, an empty set yields nothing at all: a passthrough route with no name
/// has nothing to match a ClientHello against, and Sōzu has no catch-all once
/// a listener carries SNI routes.
///
/// `listener_name` is the `proxy.tcp` listener the Gateway's port resolved to;
/// entrypoints carry it in `config.entrypoint`, exactly as a Docker-labelled
/// TCP route does.
pub fn tls_route_to_entrypoints(
    route: &TLSRoute,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
    hostnames: &[String],
    listener_name: &str,
    port: i32,
) -> Vec<Entrypoint> {
    let namespace = route.metadata.namespace.as_deref().unwrap_or("default");
    let Some(route_name) = route.metadata.name.as_deref() else {
        return Vec::new();
    };

    // Validate here rather than trusting CRD schema validation: a pattern Sōzu
    // refuses would be rejected over the command socket at `debug!` level, and
    // the entrypoint would sit in the snapshot looking applied while never
    // matching anything. Same rule as the Docker-label path.
    let hostnames: Vec<String> = hostnames
        .iter()
        .filter_map(|h| match crate::model::validate_sni(h) {
            Ok(normalized) => Some(normalized),
            Err(_) => {
                warn!(
                    "Gateway API: TLSRoute {}/{} declares hostname `{}`, which is not a routable SNI pattern (expected an exact host or one leading `*.` label, ASCII only) — dropping that hostname",
                    namespace, route_name, h
                );
                None
            }
        })
        .collect();
    if hostnames.is_empty() {
        return Vec::new();
    }
    let hostnames = &hostnames;

    route
        .spec
        .rules
        .iter()
        .enumerate()
        .flat_map(|(rule_index, rule)| {
            let backends = tls_rule_backends(rule, namespace, route_name, resolver, grants);
            if backends.is_empty() {
                return Vec::new();
            }

            hostnames
                .iter()
                .enumerate()
                .map(|(host_index, hostname)| {
                    // Keep the `…-{rule_index}` shape a single-hostname route
                    // produces, and only disambiguate when a rule fans out —
                    // same convention as the HTTP path.
                    let suffix = if hostnames.len() == 1 {
                        format!("{rule_index}")
                    } else {
                        format!("{rule_index}-h{host_index}")
                    };
                    Entrypoint {
                        // `/` separates the parts: it cannot occur in a
                        // namespace or object name, so the id is injective.
                        // Joining with `-` would not be — `a-b/c` and `a/b-c`
                        // would collide, and one route would silently evict
                        // the other from the shared storage map.
                        // The port is part of the id: one route can serve
                        // several listeners, and their entrypoint sets must not
                        // overwrite each other.
                        id: format!("{SOURCE_TAG}-tls/{namespace}/{route_name}/{port}/{suffix}"),
                        name: format!("{route_name}-{port}-{suffix}"),
                        backends: backends.clone(),
                        protocol: Protocol::Tcp,
                        config: EntrypointConfig {
                            // `hostnames` stays empty: on a TCP entrypoint the
                            // routing name lives in `sni`, and leaving both set
                            // would imply an HTTP Host match that never runs.
                            hostnames: Vec::new(),
                            sni: Some(hostname.clone()),
                            entrypoint: Some(listener_name.to_string()),
                            ..tls_entrypoint_defaults()
                        },
                        source: Some(format!("{SOURCE_TAG}-tls/{namespace}/{route_name}")),
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Resolve a TLSRoute rule's `backendRefs` to concrete pod IPs. Mirrors the
/// HTTP path's backend handling, including the ReferenceGrant check that makes
/// a cross-namespace ref opt-in.
fn tls_rule_backends(
    rule: &TLSRouteRules,
    namespace: &str,
    route_name: &str,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
) -> Vec<Backend> {
    let Some(backend_refs) = rule.backend_refs.as_ref() else {
        return Vec::new();
    };
    backend_refs
        .iter()
        .flat_map(|b| {
            let Some(port_i32) = b.port else {
                return Vec::new();
            };
            let Ok(port) = u16::try_from(port_i32) else {
                return Vec::new();
            };
            let kind_ok = b.kind.as_deref().map(|k| k == "Service").unwrap_or(true);
            let group_ok = b.group.as_deref().map(|g| g.is_empty()).unwrap_or(true);
            if !kind_ok || !group_ok {
                return Vec::new();
            }
            let target_ns = b.namespace.as_deref().unwrap_or(namespace);
            if !grants.allows(namespace, target_ns) {
                warn!(
                    "Gateway API: TLSRoute {}/{} references Service {}/{} across namespaces with no ReferenceGrant — dropping the backend",
                    namespace, route_name, target_ns, b.name
                );
                return Vec::new();
            }
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
        .collect()
}

/// `EntrypointConfig` defaults for a passthrough TCP entrypoint. Everything
/// HTTP-shaped stays off: there is no request to inspect, rewrite or
/// authenticate — only bytes to forward.
fn tls_entrypoint_defaults() -> EntrypointConfig {
    EntrypointConfig {
        hostnames: Vec::new(),
        path: None,
        tls: false,
        strip_prefix: false,
        add_prefix: None,
        https_redirect: false,
        https_redirect_port: None,
        redirect: None,
        redirect_scheme: None,
        redirect_template: None,
        rewrite_host: None,
        rewrite_path: None,
        rewrite: None,
        rewrite_port: None,
        www_authenticate: None,
        priority: 0,
        auth: None,
        forward_auth: None,
        headers: Vec::new(),
        backend_timeout: None,
        health_check: None,
        retry: None,
        circuit_breaker: None,
        rate_limit: None,
        in_flight_req: None,
        load_balancer: LoadBalancer::default(),
        sticky_session: false,
        compress: false,
        entrypoint: None,
        sni: None,
        methods: Vec::new(),
        acme: None,
        plugins: Vec::new(),
        plugin_config: std::collections::BTreeMap::new(),
        error_pages: std::collections::BTreeMap::new(),
        match_headers: Vec::new(),
        match_query: Vec::new(),
        match_client_ip: Vec::new(),
        ip_allow_list: Vec::new(),
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
    use crate::model::entrypoint::{RedirectPolicy, RedirectScheme};
    use gateway_api::apis::standard::gatewayclasses::GatewayClassSpec;
    use gateway_api::apis::standard::gateways::{GatewayListeners, GatewaySpec};
    use gateway_api::apis::standard::httproutes::{
        HTTPRouteRulesBackendRefs, HTTPRouteRulesFiltersRequestRedirect,
        HTTPRouteRulesFiltersRequestRedirectScheme, HTTPRouteRulesMatches,
        HTTPRouteRulesMatchesHeaders, HTTPRouteRulesMatchesHeadersType,
        HTTPRouteRulesMatchesMethod, HTTPRouteRulesMatchesPath, HTTPRouteRulesMatchesQueryParams,
        HTTPRouteRulesMatchesQueryParamsType, HTTPRouteSpec,
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

    /// Same guard as `httproute_shape_matches_what_we_read`, for TLSRoute.
    /// Note `spec.rules` is a bare `Vec` here, not an `Option<Vec>` — the two
    /// generated types differ, and assuming otherwise would not compile.
    #[test]
    fn tlsroute_shape_matches_what_we_read() {
        let r = TLSRoute::default();
        let _: Option<Vec<String>> = r.spec.hostnames;
        let _: Vec<TLSRouteRules> = r.spec.rules;
        let _: Option<Vec<TLSRouteParentRefs>> = r.spec.parent_refs;
    }

    /// A Gateway carrying one `TLS`/`Passthrough` listener, which is what a
    /// TLSRoute needs to attach to.
    fn tls_scope(listener_hostname: Option<&str>, port: i32) -> GatewayScope {
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
                listeners: vec![GatewayListeners {
                    name: "tls".into(),
                    port,
                    protocol: "TLS".into(),
                    hostname: listener_hostname.map(Into::into),
                    tls: Some(gateway_api::apis::standard::gateways::GatewayListenersTls {
                        mode: Some(GatewayListenersTlsMode::Passthrough),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            },
            status: Default::default(),
        });
        scope
    }

    fn tls_route(hostnames: Vec<&str>, backend_port: i32) -> TLSRoute {
        TLSRoute {
            metadata: ObjectMeta {
                name: Some("passthrough".into()),
                namespace: Some("default".into()),
                uid: Some("uid-tls-1".into()),
                ..Default::default()
            },
            spec: gateway_api::apis::experimental::tlsroutes::TLSRouteSpec {
                hostnames: Some(hostnames.into_iter().map(Into::into).collect()),
                parent_refs: Some(vec![TLSRouteParentRefs {
                    name: "gw".into(),
                    ..Default::default()
                }]),
                rules: vec![TLSRouteRules {
                    backend_refs: Some(vec![
                        gateway_api::apis::experimental::tlsroutes::TLSRouteRulesBackendRefs {
                            name: "svc".into(),
                            port: Some(backend_port),
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                }],
            },
            status: Default::default(),
        }
    }

    fn ports_8443() -> TcpListenerPorts {
        Arc::new([(8443, "tlsgw".to_string())].into_iter().collect())
    }

    #[test]
    fn tls_route_produces_one_entrypoint_per_hostname() {
        // Sōzu keys a TCP frontend on a single SNI, so a route serving two
        // names becomes two entrypoints sharing the backend set.
        let scope = tls_scope(None, 8443);
        let route = tls_route(vec!["a.example.com", "b.example.com"], 8443);
        let by_port = scope.effective_tls_hostnames_by_port(&route);
        let hostnames = by_port.get(&8443).expect("listener on 8443");

        let eps = tls_route_to_entrypoints(&route, &r1(), &scope, hostnames, "tlsgw", 8443);
        assert_eq!(eps.len(), 2);
        let snis: Vec<_> = eps.iter().filter_map(|e| e.config.sni.clone()).collect();
        assert!(snis.contains(&"a.example.com".to_string()));
        assert!(snis.contains(&"b.example.com".to_string()));
        for ep in &eps {
            assert!(matches!(ep.protocol, Protocol::Tcp));
            assert_eq!(ep.config.entrypoint.as_deref(), Some("tlsgw"));
            // The routing name lives in `sni`; a Host match would never run.
            assert!(ep.config.hostnames.is_empty());
            assert_eq!(ep.backends.len(), 1);
            assert_eq!(ep.backends[0].port, 8443);
        }
    }

    #[test]
    fn tls_route_lowercases_the_sni() {
        let scope = tls_scope(None, 8443);
        let route = tls_route(vec!["API.Example.COM"], 8443);
        let by_port = scope.effective_tls_hostnames_by_port(&route);
        let eps = tls_route_to_entrypoints(
            &route,
            &r1(),
            &scope,
            by_port.get(&8443).unwrap(),
            "tlsgw",
            8443,
        );
        assert_eq!(eps[0].config.sni.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn tls_route_without_hostnames_produces_nothing() {
        // No SNI means nothing to match a ClientHello against, and Sōzu has no
        // catch-all once a listener carries SNI routes.
        let scope = tls_scope(None, 8443);
        let route = tls_route(vec![], 8443);
        let eps = tls_route_to_entrypoints(&route, &r1(), &scope, &[], "tlsgw", 8443);
        assert!(eps.is_empty());
    }

    #[test]
    fn tls_route_with_unresolvable_backend_produces_nothing() {
        let scope = tls_scope(None, 8443);
        let route = tls_route(vec!["a.example.com"], 8443);
        let by_port = scope.effective_tls_hostnames_by_port(&route);
        let eps = tls_route_to_entrypoints(
            &route,
            &r0(),
            &scope,
            by_port.get(&8443).unwrap(),
            "tlsgw",
            8443,
        );
        assert!(eps.is_empty());
    }

    #[test]
    fn tls_route_needs_a_passthrough_listener() {
        // A `Terminate` listener means the Gateway decrypts — a different
        // feature, served by HTTPS entrypoints, so the route is not ours.
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
                listeners: vec![GatewayListeners {
                    name: "tls".into(),
                    port: 8443,
                    protocol: "TLS".into(),
                    tls: Some(gateway_api::apis::standard::gateways::GatewayListenersTls {
                        mode: Some(GatewayListenersTlsMode::Terminate),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            },
            status: Default::default(),
        });
        assert!(!scope.accepts_tls_route(&tls_route(vec!["a.example.com"], 8443)));
    }

    #[test]
    fn tls_route_ignores_a_plain_http_listener() {
        let scope = default_scope(); // gw with no listeners at all
        assert!(!scope.accepts_tls_route(&tls_route(vec!["a.example.com"], 8443)));
    }

    #[test]
    fn tls_listener_hostname_narrows_the_route() {
        // Spec: a listener hostname restricts which route hostnames it serves.
        let scope = tls_scope(Some("*.example.com"), 8443);
        let route = tls_route(vec!["a.example.com", "b.other.net"], 8443);
        let by_port = scope.effective_tls_hostnames_by_port(&route);
        assert_eq!(by_port.get(&8443), Some(&vec!["a.example.com".to_string()]));
    }

    #[test]
    fn tls_route_on_an_undeclared_port_is_not_served() {
        // The Gateway asks for 9443; only 8443 is declared under `proxy.tcp`,
        // and Sōzune does not open TCP ports on the fly.
        let scope = tls_scope(None, 9443);
        let route = tls_route(vec!["a.example.com"], 8443);
        let by_port = scope.effective_tls_hostnames_by_port(&route);
        assert!(by_port.contains_key(&9443));
        assert!(ports_8443().get(&9443).is_none());
    }

    #[test]
    fn tls_apply_and_delete_round_trip_through_storage() {
        let scope = tls_scope(None, 8443);
        let storage: Arc<RwLock<BTreeMap<String, Entrypoint>>> =
            Arc::new(RwLock::new(BTreeMap::new()));
        let index: TlsRouteIndex = Arc::new(RwLock::new(HashMap::new()));
        let route = tls_route(vec!["a.example.com"], 8443);

        assert!(apply_tls_route(
            &route,
            &storage,
            &index,
            &r1(),
            &scope,
            &ports_8443()
        ));
        assert_eq!(storage.read().unwrap().len(), 1);

        assert!(delete_tls_route(&route, &storage, &index));
        assert!(storage.read().unwrap().is_empty());
    }

    #[test]
    fn tls_apply_on_undeclared_port_tracks_the_route_with_no_entrypoints() {
        // Tracked but unserved: the route must reactivate on its own once a
        // matching `proxy.tcp` listener exists, without the apiserver
        // re-sending it.
        let scope = tls_scope(None, 9443);
        let storage: Arc<RwLock<BTreeMap<String, Entrypoint>>> =
            Arc::new(RwLock::new(BTreeMap::new()));
        let index: TlsRouteIndex = Arc::new(RwLock::new(HashMap::new()));
        let route = tls_route(vec!["a.example.com"], 8443);

        apply_tls_route(&route, &storage, &index, &r1(), &scope, &ports_8443());
        assert!(storage.read().unwrap().is_empty());
        assert_eq!(index.read().unwrap().len(), 1);

        // Declare 9443 and re-resolve: the route now lands.
        let ports = Arc::new([(9443, "tlsgw".to_string())].into_iter().collect());
        assert!(re_resolve_all_tls(&storage, &index, &r1(), &scope, &ports));
        assert_eq!(storage.read().unwrap().len(), 1);
    }

    #[test]
    fn tls_entrypoint_ids_are_stable_and_disambiguated() {
        let scope = tls_scope(None, 8443);
        let one = tls_route(vec!["a.example.com"], 8443);
        let by_port = scope.effective_tls_hostnames_by_port(&one);
        let eps = tls_route_to_entrypoints(
            &one,
            &r1(),
            &scope,
            by_port.get(&8443).unwrap(),
            "tlsgw",
            8443,
        );
        // Single hostname keeps the plain `…/{rule}` shape.
        assert_eq!(eps[0].id, "k8s-gateway-tls/default/passthrough/8443/0");

        let two = tls_route(vec!["a.example.com", "b.example.com"], 8443);
        let by_port = scope.effective_tls_hostnames_by_port(&two);
        let eps = tls_route_to_entrypoints(
            &two,
            &r1(),
            &scope,
            by_port.get(&8443).unwrap(),
            "tlsgw",
            8443,
        );
        let ids: Vec<_> = eps.iter().map(|e| e.id.as_str()).collect();
        assert!(ids.contains(&"k8s-gateway-tls/default/passthrough/8443/0-h0"));
        assert!(ids.contains(&"k8s-gateway-tls/default/passthrough/8443/0-h1"));
    }

    #[test]
    fn tls_entrypoint_ids_cannot_collide_across_routes() {
        // `-` as a separator would make `a-b/c` and `a/b-c` produce the same
        // id, and one route would silently evict the other from storage.
        let scope = tls_scope(None, 8443);

        let mut first = tls_route(vec!["x.example.com"], 8443);
        first.metadata.namespace = Some("a-b".into());
        first.metadata.name = Some("c".into());

        let mut second = tls_route(vec!["x.example.com"], 8443);
        second.metadata.namespace = Some("a".into());
        second.metadata.name = Some("b-c".into());

        let hs = vec!["x.example.com".to_string()];
        let a = tls_route_to_entrypoints(&first, &r1(), &scope, &hs, "tlsgw", 8443);
        let b = tls_route_to_entrypoints(&second, &r1(), &scope, &hs, "tlsgw", 8443);
        assert_ne!(a[0].id, b[0].id);
    }

    #[test]
    fn tls_route_with_an_unroutable_hostname_drops_only_that_name() {
        // CRD validation is not a guarantee we can rely on: a pattern Sōzu
        // refuses must be caught here, where it is visible, not in the worker.
        let scope = tls_scope(None, 8443);
        let route = tls_route(vec!["ok.example.com", "*.*.bad.example.com"], 8443);
        let eps = tls_route_to_entrypoints(
            &route,
            &r1(),
            &scope,
            &[
                "ok.example.com".to_string(),
                "*.*.bad.example.com".to_string(),
            ],
            "tlsgw",
            8443,
        );
        let snis: Vec<_> = eps.iter().filter_map(|e| e.config.sni.clone()).collect();
        assert_eq!(snis, vec!["ok.example.com".to_string()]);
    }

    #[test]
    fn tls_route_across_two_ports_keeps_each_name_on_its_own_listener() {
        // Two TLS listeners, each admitting a different name. Unioning the
        // hostnames and serving them on one port would expose a name on a
        // listener that refused it, and strand it on the one that wanted it.
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        scope.upsert_gateway(&Gateway {
            metadata: ObjectMeta {
                name: Some("gw".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "sozune".into(),
                listeners: vec![
                    GatewayListeners {
                        name: "a".into(),
                        port: 8443,
                        protocol: "TLS".into(),
                        hostname: Some("a.example.com".into()),
                        tls: Some(gateway_api::apis::standard::gateways::GatewayListenersTls {
                            mode: Some(GatewayListenersTlsMode::Passthrough),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    GatewayListeners {
                        name: "b".into(),
                        port: 9443,
                        protocol: "TLS".into(),
                        hostname: Some("b.example.com".into()),
                        tls: Some(gateway_api::apis::standard::gateways::GatewayListenersTls {
                            mode: Some(GatewayListenersTlsMode::Passthrough),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
            status: Default::default(),
        });

        let route = tls_route(vec!["a.example.com", "b.example.com"], 8443);
        let by_port = scope.effective_tls_hostnames_by_port(&route);
        assert_eq!(by_port.get(&8443), Some(&vec!["a.example.com".to_string()]));
        assert_eq!(by_port.get(&9443), Some(&vec!["b.example.com".to_string()]));
    }

    #[test]
    fn only_tls_passthrough_listeners_carry_tls_routes() {
        // Passthrough is the one shape we can serve: the bytes stay encrypted
        // and we route on the name alone.
        assert!(GatewayScope::listener_serves_tls_passthrough(&li_tls(
            "tls",
            8443,
            None,
            GatewayListenersTlsMode::Passthrough
        )));
        // Terminate would have the Gateway decrypt — that is an HTTPS
        // entrypoint's job, not this path's.
        assert!(!GatewayScope::listener_serves_tls_passthrough(&li_tls(
            "tls",
            8443,
            None,
            GatewayListenersTlsMode::Terminate
        )));
        // An HTTP listener has no ClientHello to preread.
        assert!(!GatewayScope::listener_serves_tls_passthrough(&li(
            "http", 80, None
        )));
    }

    #[test]
    fn tls_protocol_match_is_case_insensitive() {
        // The Gateway API says `TLS`, but the field is a free-form string and
        // manifests in the wild are not always consistent.
        let mut lower = li_tls("tls", 8443, None, GatewayListenersTlsMode::Passthrough);
        lower.protocol = "tls".into();
        assert!(GatewayScope::listener_serves_tls_passthrough(&lower));
    }

    #[test]
    fn a_tls_listener_without_a_mode_is_not_passthrough() {
        // `tls.mode` defaults to Terminate per spec, so an unset mode must not
        // be read as passthrough.
        let mut no_mode = li_tls("tls", 8443, None, GatewayListenersTlsMode::Passthrough);
        no_mode.tls_mode = None;
        assert!(!GatewayScope::listener_serves_tls_passthrough(&no_mode));
    }

    #[test]
    fn tcp_listener_ports_maps_port_to_name() {
        let listeners = vec![
            crate::config::TcpListenerConfig {
                name: "tlsgw".into(),
                listen: 8443,
                ip_allow_list: Vec::new(),
                rate_limit: None,
                sni_preread_timeout: None,
                sni_preread_max_bytes: None,
            },
            crate::config::TcpListenerConfig {
                name: "pg".into(),
                listen: 5432,
                ip_allow_list: Vec::new(),
                rate_limit: None,
                sni_preread_timeout: None,
                sni_preread_max_bytes: None,
            },
        ];
        let ports = tcp_listener_ports(&listeners);
        assert_eq!(ports.get(&8443).map(String::as_str), Some("tlsgw"));
        assert_eq!(ports.get(&5432).map(String::as_str), Some("pg"));
        assert!(ports.get(&443).is_none());
    }

    // ---------- TCPRoute ----------

    /// A Gateway with one `TCP` listener on `port`.
    fn tcp_scope(port: i32) -> GatewayScope {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        scope.upsert_gateway(&Gateway {
            metadata: ObjectMeta {
                name: Some("gw".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "sozune".into(),
                listeners: vec![GatewayListeners {
                    name: "tcp".into(),
                    port,
                    protocol: "TCP".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            status: Default::default(),
        });
        scope
    }

    fn tcp_route(backend_port: i32) -> TCPRoute {
        TCPRoute {
            metadata: ObjectMeta {
                name: Some("raw".into()),
                namespace: Some("default".into()),
                uid: Some("uid-tcp-1".into()),
                ..Default::default()
            },
            spec: gateway_api::apis::experimental::tcproutes::TCPRouteSpec {
                parent_refs: Some(vec![TCPRouteParentRefs {
                    name: "gw".into(),
                    ..Default::default()
                }]),
                rules: vec![TCPRouteRules {
                    backend_refs: Some(vec![
                        gateway_api::apis::experimental::tcproutes::TCPRouteRulesBackendRefs {
                            name: "svc".into(),
                            port: Some(backend_port),
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                }],
            },
            status: Default::default(),
        }
    }

    fn tcp_ports() -> TcpListenerPorts {
        Arc::new([(9000, "tcpgw".to_string())].into_iter().collect())
    }

    #[test]
    fn tcp_route_produces_one_catch_all_entrypoint_per_rule() {
        let scope = tcp_scope(9000);
        let route = tcp_route(9000);
        let ports = scope.effective_tcp_ports(&route);
        assert!(ports.contains(&9000));

        let eps = tcp_route_to_entrypoints(&route, &r1(), &scope, "tcpgw", 9000);
        assert_eq!(eps.len(), 1);
        let ep = &eps[0];
        assert!(matches!(ep.protocol, Protocol::Tcp));
        assert_eq!(ep.config.entrypoint.as_deref(), Some("tcpgw"));
        // Raw TCP: no SNI, whole port forwarded.
        assert_eq!(ep.config.sni, None);
        assert!(ep.config.hostnames.is_empty());
        assert_eq!(ep.backends.len(), 1);
        assert_eq!(ep.backends[0].port, 9000);
    }

    #[test]
    fn tcp_route_needs_a_tcp_listener() {
        // A TLS listener is not a TCP listener — a TCPRoute must not attach.
        let scope = tls_scope(None, 9000);
        assert!(!scope.accepts_tcp_route(&tcp_route(9000)));
    }

    #[test]
    fn tcp_route_ignores_a_plain_http_listener() {
        let scope = default_scope(); // gw with no listeners
        assert!(!scope.accepts_tcp_route(&tcp_route(9000)));
    }

    #[test]
    fn tcp_route_with_unresolvable_backend_produces_nothing() {
        let scope = tcp_scope(9000);
        let eps = tcp_route_to_entrypoints(&tcp_route(9000), &r0(), &scope, "tcpgw", 9000);
        assert!(eps.is_empty());
    }

    #[test]
    fn tcp_apply_and_delete_round_trip_through_storage() {
        let scope = tcp_scope(9000);
        let storage: Arc<RwLock<BTreeMap<String, Entrypoint>>> =
            Arc::new(RwLock::new(BTreeMap::new()));
        let index: TcpRouteIndex = Arc::new(RwLock::new(HashMap::new()));
        let route = tcp_route(9000);

        assert!(apply_tcp_route(
            &route,
            &storage,
            &index,
            &r1(),
            &scope,
            &tcp_ports()
        ));
        assert_eq!(storage.read().unwrap().len(), 1);

        assert!(delete_tcp_route(&route, &storage, &index));
        assert!(storage.read().unwrap().is_empty());
    }

    #[test]
    fn tcp_apply_on_undeclared_port_tracks_the_route_with_no_entrypoints() {
        // Gateway asks for 9443; only 9000 is declared under `proxy.tcp`.
        let scope = tcp_scope(9443);
        let storage: Arc<RwLock<BTreeMap<String, Entrypoint>>> =
            Arc::new(RwLock::new(BTreeMap::new()));
        let index: TcpRouteIndex = Arc::new(RwLock::new(HashMap::new()));
        let route = tcp_route(9000);

        apply_tcp_route(&route, &storage, &index, &r1(), &scope, &tcp_ports());
        assert!(storage.read().unwrap().is_empty());
        assert_eq!(index.read().unwrap().len(), 1);

        // Declare 9443 and re-resolve: the route lands.
        let ports = Arc::new([(9443, "tcpgw".to_string())].into_iter().collect());
        assert!(re_resolve_all_tcp(&storage, &index, &r1(), &scope, &ports));
        assert_eq!(storage.read().unwrap().len(), 1);
    }

    #[test]
    fn tcp_entrypoint_ids_cannot_collide_with_tls() {
        // The `-tcp/` vs `-tls/` id prefix keeps the two route kinds apart in
        // the shared storage map.
        let tcp_scope = tcp_scope(9000);
        let tcp = tcp_route(9000);
        let tcp_eps = tcp_route_to_entrypoints(&tcp, &r1(), &tcp_scope, "gw", 9000);
        assert!(tcp_eps[0].id.starts_with("k8s-gateway-tcp/"));
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

    fn header_match(
        name: &str,
        value: &str,
        ty: HTTPRouteRulesMatchesHeadersType,
    ) -> HTTPRouteRulesMatches {
        HTTPRouteRulesMatches {
            headers: Some(vec![HTTPRouteRulesMatchesHeaders {
                name: name.into(),
                value: value.into(),
                r#type: Some(ty),
            }]),
            ..Default::default()
        }
    }

    fn query_match(
        name: &str,
        value: &str,
        ty: HTTPRouteRulesMatchesQueryParamsType,
    ) -> HTTPRouteRulesMatches {
        HTTPRouteRulesMatches {
            query_params: Some(vec![HTTPRouteRulesMatchesQueryParams {
                name: name.into(),
                value: value.into(),
                r#type: Some(ty),
            }]),
            ..Default::default()
        }
    }

    fn method_match(method: HTTPRouteRulesMatchesMethod) -> HTTPRouteRulesMatches {
        HTTPRouteRulesMatches {
            method: Some(method),
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
        assert!(route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs).is_empty());
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
        assert!(route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs).is_empty());
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
        assert!(route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs).is_empty());
    }

    #[test]
    fn rule_without_port_is_skipped() {
        let mut b = backend("svc", 0);
        b.port = None;
        let r = route_with(vec![rule(None, vec![b])], vec!["app.example.com".into()]);
        assert!(route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs).is_empty());
    }

    #[test]
    fn single_rule_produces_one_entrypoint_with_resolved_pod_ip() {
        let r = route_with(
            vec![rule(None, vec![backend("api", 8080)])],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
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
        assert!(route_to_entrypoints(&r, &r0(), &AllowAllBackendRefs).is_empty());
    }

    #[test]
    fn multiple_pod_ips_produce_multiple_backends() {
        let r = route_with(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        let resolver = StubResolver(vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
        let eps = route_to_entrypoints(&r, &resolver, &AllowAllBackendRefs);
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
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
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
        let eps = route_to_entrypoints(&r, &CrossNsResolver, &AllowAllBackendRefs);
        assert_eq!(eps[0].backends[0].address, "10.1.0.1");
    }

    // A ReferenceGrant in `to_ns` trusting `HTTPRoute` from `from_ns`.
    fn reference_grant(to_ns: &str, from_ns: &str) -> ReferenceGrant {
        use gateway_api::apis::standard::referencegrants::{
            ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo,
        };
        ReferenceGrant {
            metadata: ObjectMeta {
                namespace: Some(to_ns.into()),
                name: Some("grant".into()),
                ..Default::default()
            },
            spec: ReferenceGrantSpec {
                from: vec![ReferenceGrantFrom {
                    group: GATEWAY_API_GROUP.into(),
                    kind: "HTTPRoute".into(),
                    namespace: from_ns.into(),
                }],
                to: vec![ReferenceGrantTo {
                    group: String::new(),
                    kind: "Service".into(),
                    name: None,
                }],
            },
        }
    }

    #[test]
    fn cross_namespace_backend_without_grant_is_dropped() {
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
        // Empty scope: no ReferenceGrant, so the cross-namespace ref is
        // refused and the route resolves to zero entrypoints.
        let scope = GatewayScope::new();
        assert!(route_to_entrypoints(&r, &CrossNsResolver, &scope).is_empty());
    }

    #[test]
    fn cross_namespace_backend_with_grant_resolves() {
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
        // Route lives in the default namespace; a grant in "other" trusts it.
        let r = route_with(vec![rule(None, vec![b])], vec!["app.example.com".into()]);
        let scope = GatewayScope::new();
        assert!(scope.upsert_reference_grant(&reference_grant("other", "default")));
        let eps = route_to_entrypoints(&r, &CrossNsResolver, &scope);
        assert_eq!(eps[0].backends[0].address, "10.1.0.1");
    }

    #[test]
    fn reference_grant_removal_revokes_access() {
        let scope = GatewayScope::new();
        let grant = reference_grant("other", "default");
        assert!(scope.upsert_reference_grant(&grant));
        assert!(scope.allows_backend_ref("default", "other"));
        assert!(scope.remove_reference_grant(&grant));
        assert!(!scope.allows_backend_ref("default", "other"));
    }

    #[test]
    fn same_namespace_backend_never_needs_grant() {
        let scope = GatewayScope::new();
        // No grant at all, yet same-namespace is always allowed.
        assert!(scope.allows_backend_ref("app", "app"));
    }

    #[test]
    fn grant_to_secret_does_not_authorise_service_ref() {
        use gateway_api::apis::standard::referencegrants::{
            ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo,
        };
        let grant = ReferenceGrant {
            metadata: ObjectMeta {
                namespace: Some("other".into()),
                name: Some("grant".into()),
                ..Default::default()
            },
            spec: ReferenceGrantSpec {
                from: vec![ReferenceGrantFrom {
                    group: GATEWAY_API_GROUP.into(),
                    kind: "HTTPRoute".into(),
                    namespace: "default".into(),
                }],
                // Grants access to a Secret, not a Service — irrelevant to
                // backendRef resolution.
                to: vec![ReferenceGrantTo {
                    group: String::new(),
                    kind: "Secret".into(),
                    name: None,
                }],
            },
        };
        let scope = GatewayScope::new();
        // Nothing changed: the grant doesn't authorise any Service ref.
        assert!(!scope.upsert_reference_grant(&grant));
        assert!(!scope.allows_backend_ref("default", "other"));
    }

    #[test]
    fn grant_from_tcproute_authorises_a_cross_namespace_service_ref() {
        use gateway_api::apis::standard::referencegrants::{
            ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo,
        };
        // A ReferenceGrant naming TCPRoute (not HTTPRoute) must be recognised,
        // or a cross-namespace TCPRoute backend can never be reached.
        let grant = ReferenceGrant {
            metadata: ObjectMeta {
                namespace: Some("other".into()),
                name: Some("grant".into()),
                ..Default::default()
            },
            spec: ReferenceGrantSpec {
                from: vec![ReferenceGrantFrom {
                    group: GATEWAY_API_GROUP.into(),
                    kind: "TCPRoute".into(),
                    namespace: "default".into(),
                }],
                to: vec![ReferenceGrantTo {
                    group: String::new(),
                    kind: "Service".into(),
                    name: None,
                }],
            },
        };
        let scope = GatewayScope::new();
        assert!(scope.upsert_reference_grant(&grant));
        assert!(scope.allows_backend_ref("default", "other"));
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
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
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
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
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
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        // Backend still produces an entrypoint, but without a path config.
        assert_eq!(eps.len(), 1);
        assert!(eps[0].config.path.is_none());
    }

    #[test]
    fn exact_header_match_becomes_a_match_condition() {
        let r = route_with(
            vec![rule(
                Some(vec![header_match(
                    "X-Canary",
                    "yes",
                    HTTPRouteRulesMatchesHeadersType::Exact,
                )]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].config.match_headers.len(), 1);
        assert_eq!(eps[0].config.match_headers[0].key, "X-Canary");
        assert_eq!(eps[0].config.match_headers[0].value, "yes");
    }

    #[test]
    fn exact_query_match_becomes_a_match_condition() {
        let r = route_with(
            vec![rule(
                Some(vec![query_match(
                    "debug",
                    "1",
                    HTTPRouteRulesMatchesQueryParamsType::Exact,
                )]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].config.match_query.len(), 1);
        assert_eq!(eps[0].config.match_query[0].key, "debug");
        assert_eq!(eps[0].config.match_query[0].value, "1");
    }

    #[test]
    fn method_match_becomes_an_uppercase_verb() {
        let r = route_with(
            vec![rule(
                Some(vec![method_match(HTTPRouteRulesMatchesMethod::Post)]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].config.methods, vec!["POST".to_string()]);
    }

    #[test]
    fn header_query_and_method_are_anded_on_one_match() {
        let mut m = header_match("X-Canary", "yes", HTTPRouteRulesMatchesHeadersType::Exact);
        m.query_params = Some(vec![HTTPRouteRulesMatchesQueryParams {
            name: "debug".into(),
            value: "1".into(),
            r#type: Some(HTTPRouteRulesMatchesQueryParamsType::Exact),
        }]);
        m.method = Some(HTTPRouteRulesMatchesMethod::Get);
        let r = route_with(
            vec![rule(Some(vec![m]), vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].config.match_headers.len(), 1);
        assert_eq!(eps[0].config.match_query.len(), 1);
        assert_eq!(eps[0].config.methods, vec!["GET".to_string()]);
    }

    #[test]
    fn regex_header_match_is_reported_unsupported() {
        let r = route_with(
            vec![rule(
                Some(vec![header_match(
                    "X-Canary",
                    "^v[0-9]+$",
                    HTTPRouteRulesMatchesHeadersType::RegularExpression,
                )]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        assert!(route_has_unsupported_matches(&r));
    }

    #[test]
    fn regex_query_match_is_reported_unsupported() {
        let r = route_with(
            vec![rule(
                Some(vec![query_match(
                    "v",
                    "^[0-9]+$",
                    HTTPRouteRulesMatchesQueryParamsType::RegularExpression,
                )]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        assert!(route_has_unsupported_matches(&r));
    }

    #[test]
    fn exact_matches_are_not_reported_unsupported() {
        let r = route_with(
            vec![rule(
                Some(vec![
                    header_match("X-A", "1", HTTPRouteRulesMatchesHeadersType::Exact),
                    method_match(HTTPRouteRulesMatchesMethod::Delete),
                ]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        assert!(!route_has_unsupported_matches(&r));
    }

    #[test]
    fn non_service_kind_backend_is_skipped() {
        let mut b = backend("svc", 80);
        b.kind = Some("CustomResource".into());
        let r = route_with(vec![rule(None, vec![b])], vec!["app.example.com".into()]);
        assert!(route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs).is_empty());
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
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps[0].backends[0].weight, 42);
    }

    // ---------- Filters & multi-match tests ----------

    use crate::model::entrypoint::{HeaderDirection, PathRewrite};
    use gateway_api::apis::standard::httproutes::{
        HTTPRouteRulesFilters, HTTPRouteRulesFiltersRequestHeaderModifier,
        HTTPRouteRulesFiltersRequestHeaderModifierSet, HTTPRouteRulesFiltersResponseHeaderModifier,
        HTTPRouteRulesFiltersResponseHeaderModifierSet, HTTPRouteRulesFiltersUrlRewrite,
        HTTPRouteRulesFiltersUrlRewritePath, HTTPRouteRulesFiltersUrlRewritePathType,
    };

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
    fn route_with_unsupported_filter_is_dropped_entirely() {
        // Honouring a filter we don't understand is worse than refusing
        // the route — silently routing as if the filter weren't there
        // breaks user intent. An empty filter struct carries no variant
        // we recognise, so it counts as unsupported.
        let r = route_with(
            vec![rule_with_filter(
                vec![backend("api", 80)],
                vec![HTTPRouteRulesFilters::default()],
            )],
            vec!["app.example.com".into()],
        );
        assert!(route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs).is_empty());
        assert!(route_has_unsupported_filters(&r));
    }

    #[test]
    fn route_with_request_redirect_maps_to_native_redirect() {
        // A scheme-only requestRedirect (the HTTP→HTTPS case) is mapped
        // onto Sōzu's native frontend redirect instead of being dropped.
        let redirect = HTTPRouteRulesFilters {
            request_redirect: Some(HTTPRouteRulesFiltersRequestRedirect {
                scheme: Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = route_with(
            vec![rule_with_filter(vec![backend("api", 80)], vec![redirect])],
            vec!["app.example.com".into()],
        );
        assert!(!route_has_unsupported_filters(&r));
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].config.redirect, Some(RedirectPolicy::Permanent));
        assert_eq!(
            eps[0].config.redirect_scheme,
            Some(RedirectScheme::UseHttps)
        );
    }

    #[test]
    fn route_with_request_header_modifier_populates_headers() {
        let filter = HTTPRouteRulesFilters {
            request_header_modifier: Some(HTTPRouteRulesFiltersRequestHeaderModifier {
                set: Some(vec![HTTPRouteRulesFiltersRequestHeaderModifierSet {
                    name: "X-Env".into(),
                    value: "prod".into(),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = route_with(
            vec![rule_with_filter(vec![backend("api", 80)], vec![filter])],
            vec!["app.example.com".into()],
        );
        assert!(!route_has_unsupported_filters(&r));
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].config.headers.len(), 1);
        assert_eq!(eps[0].config.headers[0].name, "X-Env");
        assert_eq!(eps[0].config.headers[0].value, "prod");
        assert_eq!(eps[0].config.headers[0].direction, HeaderDirection::Request);
    }

    #[test]
    fn route_with_response_header_modifier_uses_response_direction() {
        let filter = HTTPRouteRulesFilters {
            response_header_modifier: Some(HTTPRouteRulesFiltersResponseHeaderModifier {
                set: Some(vec![HTTPRouteRulesFiltersResponseHeaderModifierSet {
                    name: "X-Powered-By".into(),
                    value: "sozune".into(),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = route_with(
            vec![rule_with_filter(vec![backend("api", 80)], vec![filter])],
            vec!["app.example.com".into()],
        );
        assert!(!route_has_unsupported_filters(&r));
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps[0].config.headers.len(), 1);
        assert_eq!(
            eps[0].config.headers[0].direction,
            HeaderDirection::Response
        );
    }

    #[test]
    fn route_mixing_redirect_and_header_modifier_is_accepted() {
        let filter = HTTPRouteRulesFilters {
            request_redirect: Some(HTTPRouteRulesFiltersRequestRedirect {
                scheme: Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
                ..Default::default()
            }),
            request_header_modifier: Some(HTTPRouteRulesFiltersRequestHeaderModifier {
                set: Some(vec![HTTPRouteRulesFiltersRequestHeaderModifierSet {
                    name: "X-Env".into(),
                    value: "prod".into(),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = route_with(
            vec![rule_with_filter(vec![backend("api", 80)], vec![filter])],
            vec!["app.example.com".into()],
        );
        assert!(!route_has_unsupported_filters(&r));
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].config.redirect, Some(RedirectPolicy::Permanent));
        assert_eq!(eps[0].config.headers.len(), 1);
    }

    #[test]
    fn route_with_request_mirror_is_still_unsupported() {
        let filter = HTTPRouteRulesFilters {
            request_mirror: Some(Default::default()),
            ..Default::default()
        };
        let r = route_with(
            vec![rule_with_filter(vec![backend("api", 80)], vec![filter])],
            vec!["app.example.com".into()],
        );
        assert!(route_has_unsupported_filters(&r));
        assert!(route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs).is_empty());
    }

    #[test]
    fn route_with_url_rewrite_replace_prefix_maps_to_rewrite_field() {
        let filter = HTTPRouteRulesFilters {
            url_rewrite: Some(HTTPRouteRulesFiltersUrlRewrite {
                hostname: None,
                path: Some(HTTPRouteRulesFiltersUrlRewritePath {
                    replace_full_path: None,
                    replace_prefix_match: Some("/v2".into()),
                    r#type: HTTPRouteRulesFiltersUrlRewritePathType::ReplacePrefixMatch,
                }),
            }),
            ..Default::default()
        };
        let r = route_with(
            vec![rule_with_filter(vec![backend("api", 80)], vec![filter])],
            vec!["app.example.com".into()],
        );
        assert!(!route_has_unsupported_filters(&r));
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        let rw = eps[0].config.rewrite.as_ref().unwrap();
        assert_eq!(rw.path, Some(PathRewrite::ReplacePrefixMatch("/v2".into())));
        assert_eq!(rw.hostname, None);
    }

    #[test]
    fn route_with_url_rewrite_hostname_sets_rewrite_hostname() {
        let filter = HTTPRouteRulesFilters {
            url_rewrite: Some(HTTPRouteRulesFiltersUrlRewrite {
                hostname: Some("internal.svc".into()),
                path: None,
            }),
            ..Default::default()
        };
        let r = route_with(
            vec![rule_with_filter(vec![backend("api", 80)], vec![filter])],
            vec!["app.example.com".into()],
        );
        assert!(!route_has_unsupported_filters(&r));
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        let rw = eps[0].config.rewrite.as_ref().unwrap();
        assert_eq!(rw.hostname.as_deref(), Some("internal.svc"));
        assert_eq!(rw.path, None);
    }

    #[test]
    fn route_mixing_redirect_and_url_rewrite_is_unsupported() {
        // Conflicting intents over the frontend rewrite — the whole route
        // is dropped, not partially applied.
        let redirect = HTTPRouteRulesFilters {
            request_redirect: Some(HTTPRouteRulesFiltersRequestRedirect {
                scheme: Some(HTTPRouteRulesFiltersRequestRedirectScheme::Https),
                ..Default::default()
            }),
            ..Default::default()
        };
        let rewrite = HTTPRouteRulesFilters {
            url_rewrite: Some(HTTPRouteRulesFiltersUrlRewrite {
                hostname: Some("internal.svc".into()),
                path: None,
            }),
            ..Default::default()
        };
        let r = route_with(
            vec![rule_with_filter(
                vec![backend("api", 80)],
                vec![redirect, rewrite],
            )],
            vec!["app.example.com".into()],
        );
        assert!(route_has_unsupported_filters(&r));
        assert!(route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs).is_empty());
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
        assert_eq!(
            route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs).len(),
            1
        );
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
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
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
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
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
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
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

    // ---------- Gateway / GatewayClass status tests ----------
    //
    // Same contract as the route status tests: the pure builders and the
    // condition merge encode which conditions sōzune owns and how they
    // slot into a status that may carry conditions owned by other actors.
    // The patch writers themselves are apiserver-bound and covered by e2e.

    fn find_condition(conds: &[Condition], ty: &str) -> Condition {
        conds
            .iter()
            .find(|c| c.type_ == ty)
            .expect("expected condition not found")
            .clone()
    }

    #[test]
    fn build_gateway_conditions_accepted_flips_both_true() {
        let gw = gateway("default", "gw", "sozune");
        let conds = build_gateway_conditions(&gw, true);
        assert_eq!(conds.len(), 2);
        assert_eq!(
            find_condition(&conds, CONDITION_TYPE_ACCEPTED).status,
            "True"
        );
        assert_eq!(
            find_condition(&conds, CONDITION_TYPE_PROGRAMMED).status,
            "True"
        );
    }

    #[test]
    fn build_gateway_conditions_not_accepted_flips_both_false() {
        let gw = gateway("default", "gw", "foreign");
        let conds = build_gateway_conditions(&gw, false);
        assert_eq!(
            find_condition(&conds, CONDITION_TYPE_ACCEPTED).status,
            "False"
        );
        assert_eq!(
            find_condition(&conds, CONDITION_TYPE_PROGRAMMED).status,
            "False"
        );
    }

    #[test]
    fn build_gateway_conditions_carry_observed_generation() {
        let mut gw = gateway("default", "gw", "sozune");
        gw.metadata.generation = Some(7);
        let conds = build_gateway_conditions(&gw, true);
        assert!(
            conds.iter().all(|c| c.observed_generation == Some(7)),
            "every condition must pin the observed generation"
        );
    }

    #[test]
    fn build_gatewayclass_conditions_is_a_single_accepted_true() {
        let c = class("sozune", SOZUNE_CONTROLLER_NAME);
        let conds = build_gatewayclass_conditions(&c);
        assert_eq!(conds.len(), 1);
        assert_eq!(conds[0].type_, CONDITION_TYPE_ACCEPTED);
        assert_eq!(conds[0].status, "True");
    }

    #[test]
    fn merge_conditions_preserves_foreign_types() {
        let existing = vec![Condition {
            type_: "Programmed".into(),
            status: "True".into(),
            reason: "Programmed".into(),
            message: "set by another actor".into(),
            last_transition_time: Time(k8s_openapi::chrono::Utc::now()),
            observed_generation: Some(1),
        }];
        // Ours only sets Accepted; the foreign Programmed must survive.
        let ours = build_gatewayclass_conditions(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let (merged, changed) = merge_conditions(Some(&existing), ours);
        assert!(changed, "adding a new Accepted type is a change");
        assert_eq!(merged.len(), 2);
        assert_eq!(
            find_condition(&merged, "Programmed").message,
            "set by another actor"
        );
        assert_eq!(find_condition(&merged, "Accepted").status, "True");
    }

    #[test]
    fn merge_conditions_skips_when_only_timestamp_differs() {
        let gw = gateway("default", "gw", "sozune");
        let first = build_gateway_conditions(&gw, true);
        // Rebuild — same outcome, only last_transition_time differs.
        let second = build_gateway_conditions(&gw, true);
        let (_, changed) = merge_conditions(Some(&first), second);
        assert!(
            !changed,
            "a differing timestamp alone must not trigger a write"
        );
    }

    #[test]
    fn merge_conditions_detects_status_flip() {
        let gw = gateway("default", "gw", "sozune");
        let accepted = build_gateway_conditions(&gw, true);
        let rejected = build_gateway_conditions(&gw, false);
        let (merged, changed) = merge_conditions(Some(&accepted), rejected);
        assert!(changed);
        assert_eq!(
            find_condition(&merged, CONDITION_TYPE_ACCEPTED).status,
            "False"
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

    fn li(name: &str, port: i32, hostname: Option<&str>) -> ListenerInfo {
        ListenerInfo {
            name: name.into(),
            port,
            hostname: hostname.map(Into::into),
            protocol: "HTTP".into(),
            tls_mode: None,
        }
    }

    /// A `TLS` listener in the given mode — what a TLSRoute needs to attach to.
    fn li_tls(
        name: &str,
        port: i32,
        hostname: Option<&str>,
        mode: GatewayListenersTlsMode,
    ) -> ListenerInfo {
        ListenerInfo {
            name: name.into(),
            port,
            hostname: hostname.map(Into::into),
            protocol: "TLS".into(),
            tls_mode: Some(mode),
        }
    }

    // ---------- Listener selection / hostname intersection ----------

    #[test]
    fn unset_section_and_port_selects_any_listener() {
        let listeners = vec![li("web", 80, None), li("admin", 8080, None)];
        assert!(parent_ref_selects_listener(&parent("gw"), &listeners));
    }

    #[test]
    fn section_name_must_match_a_listener() {
        let listeners = vec![li("web", 80, None)];
        let mut p = parent("gw");
        p.section_name = Some("web".into());
        assert!(parent_ref_selects_listener(&p, &listeners));
        p.section_name = Some("nope".into());
        assert!(!parent_ref_selects_listener(&p, &listeners));
    }

    #[test]
    fn port_must_match_a_listener() {
        let listeners = vec![li("web", 80, None)];
        let mut p = parent("gw");
        p.port = Some(80);
        assert!(parent_ref_selects_listener(&p, &listeners));
        p.port = Some(8080);
        assert!(!parent_ref_selects_listener(&p, &listeners));
    }

    #[test]
    fn section_and_port_must_be_satisfied_by_the_same_listener() {
        let listeners = vec![li("web", 80, None), li("admin", 8080, None)];
        let mut p = parent("gw");
        p.section_name = Some("web".into());
        p.port = Some(8080); // web is 80, admin is 8080 — no single listener matches
        assert!(!parent_ref_selects_listener(&p, &listeners));
        p.port = Some(80);
        assert!(parent_ref_selects_listener(&p, &listeners));
    }

    #[test]
    fn listener_without_hostname_passes_route_hostnames_through() {
        let listeners = vec![li("web", 80, None)];
        let got = intersect_hostnames(&["a.example.com".into()], &listeners);
        assert_eq!(got, Some(vec!["a.example.com".to_string()]));
    }

    #[test]
    fn listener_hostname_narrows_route_hostnames() {
        let listeners = vec![li("web", 80, Some("*.example.com"))];
        let got = intersect_hostnames(&["a.example.com".into(), "b.other.com".into()], &listeners);
        assert_eq!(got, Some(vec!["a.example.com".to_string()]));
    }

    #[test]
    fn no_hostname_overlap_yields_none() {
        let listeners = vec![li("web", 80, Some("example.com"))];
        let got = intersect_hostnames(&["a.other.com".into()], &listeners);
        assert_eq!(got, None);
    }

    #[test]
    fn route_without_hostnames_inherits_listener_hostname() {
        let listeners = vec![li("web", 80, Some("example.com"))];
        let got = intersect_hostnames(&[], &listeners);
        assert_eq!(got, Some(vec!["example.com".to_string()]));
    }

    #[test]
    fn wildcard_hostname_compatibility() {
        assert!(hostnames_compatible("*.example.com", "api.example.com"));
        assert!(hostnames_compatible("api.example.com", "*.example.com"));
        assert!(!hostnames_compatible("*.example.com", "example.com"));
        assert!(!hostnames_compatible("*.example.com", "api.other.com"));
        assert!(hostnames_compatible("a.example.com", "a.example.com"));
    }

    #[test]
    fn scope_rejects_parent_ref_naming_an_unknown_listener() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        gw.spec.listeners = vec![GatewayListeners {
            name: "web".into(),
            port: 80,
            protocol: "HTTP".into(),
            ..Default::default()
        }];
        scope.upsert_gateway(&gw);

        let mut good = parent("gw");
        good.section_name = Some("web".into());
        let mut bad = parent("gw");
        bad.section_name = Some("admin".into());

        let r_good = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![good],
        );
        let r_bad = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![bad],
        );
        assert!(scope.accepts_route(&r_good));
        assert!(!scope.accepts_route(&r_bad));
    }

    #[test]
    fn scope_notifies_when_listeners_change() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        gw.spec.listeners = vec![GatewayListeners {
            name: "web".into(),
            port: 80,
            protocol: "HTTP".into(),
            ..Default::default()
        }];
        assert!(scope.upsert_gateway(&gw), "first apply is a change");
        assert!(!scope.upsert_gateway(&gw), "same listeners is a no-op");
        gw.spec.listeners.push(GatewayListeners {
            name: "admin".into(),
            port: 8080,
            protocol: "HTTP".into(),
            ..Default::default()
        });
        assert!(
            scope.upsert_gateway(&gw),
            "adding a listener must be seen as a change"
        );
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
