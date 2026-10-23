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
use super::gateway_tls::SecretCertificate;
use crate::model::{
    Backend, Entrypoint, EntrypointConfig, LoadBalancer, PathConfig, PathRuleType, Protocol,
};
use futures_util::StreamExt;
use gateway_api::apis::experimental::tcproutes::{TCPRoute, TCPRouteParentRefs, TCPRouteRules};
use gateway_api::apis::experimental::tlsroutes::{TLSRoute, TLSRouteParentRefs, TLSRouteRules};
use gateway_api::apis::experimental::udproutes::{UDPRoute, UDPRouteParentRefs, UDPRouteRules};
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::{
    Gateway, GatewayListeners, GatewayListenersAllowedRoutesNamespacesFrom,
    GatewayListenersTlsCertificateRefs, GatewayListenersTlsMode,
};
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

/// Whether a route comes from the Gateway API: only such a route may open a
/// port of `proxy.gateway_ports`.
pub fn is_gateway_route(entrypoint: &Entrypoint) -> bool {
    entrypoint
        .source
        .as_deref()
        .and_then(|s| s.strip_prefix(SOURCE_TAG))
        .is_some_and(|rest| rest.starts_with('-'))
}

/// Route watchers that consume `GatewayScope::changed()`: HTTPRoute, TLSRoute,
/// TCPRoute and UDPRoute. Each scope mutation posts one permit per watcher so
/// all re-resolve immediately instead of one waiting out its periodic tick.
/// Bump this when adding another route watcher.
const SCOPE_SUBSCRIBERS: usize = 4;

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
    /// `allowedRoutes.namespaces.from`: which namespaces' routes may attach.
    pub allowed_namespaces: AllowedNamespaces,
    /// `allowedRoutes.kinds`, as route kinds of the Gateway API group. `None`
    /// when unset or empty: the protocol decides, which the per-kind listener
    /// predicates already do.
    pub allowed_kinds: Option<Vec<String>>,
}

/// `allowedRoutes.namespaces.from` of a Gateway listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowedNamespaces {
    /// Only routes in the Gateway's own namespace (the API default).
    Same,
    /// Routes in any namespace.
    All,
    /// Routes in namespaces matching a label selector. Namespace labels are
    /// not watched, so no route is admitted: failing closed keeps a listener
    /// from serving namespaces it did not mean to.
    Selector,
}

impl ListenerInfo {
    /// True iff this listener's `allowedRoutes` lets a `kind` route from
    /// `route_ns` attach to it, on a Gateway in `gateway_ns`.
    pub(crate) fn admits(&self, gateway_ns: &str, route_ns: &str, kind: &str) -> bool {
        let namespace_ok = match self.allowed_namespaces {
            AllowedNamespaces::Same => route_ns == gateway_ns,
            AllowedNamespaces::All => true,
            AllowedNamespaces::Selector => false,
        };
        let kind_ok = self
            .allowed_kinds
            .as_ref()
            .is_none_or(|kinds| kinds.iter().any(|k| k == kind));
        namespace_ok && kind_ok
    }
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
impl_parent_ref!(UDPRouteParentRefs);

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
    /// The last Gateway object seen for each accepted Gateway, so its status
    /// can be rewritten when the routes attached to it change.
    gateway_objects: HashMap<(String, String), Gateway>,
    /// The listeners each route attaches to, keyed by route kind and uid:
    /// what `attachedRoutes` counts on a listener's status.
    attachments: HashMap<(&'static str, String), Vec<ListenerKey>>,
    /// The ports Sōzune listens on, from `config.yaml`.
    served: ServedPorts,
    /// Where Gateway status rewrites go when attachments change.
    status_tx: Option<mpsc::Sender<StatusWrite>>,
    /// The `kubernetes.io/tls` Secrets, keyed by `(namespace, name)`: the
    /// certificate each holds, or why it cannot be used.
    tls_secrets: HashMap<(String, String), Result<Arc<SecretCertificate>, String>>,
    /// The TLS Secrets each Ingress names in `spec.tls[].secretName`, by
    /// Ingress `namespace/name`.
    ingress_secrets: HashMap<String, Vec<(String, String)>>,
    /// What each ReferenceGrant lets Gateways reference among Secrets, by
    /// grant `(namespace, name)`.
    secret_grants: HashMap<(String, String), SecretGrant>,
}

/// The Secrets a ReferenceGrant lets Gateways of other namespaces name in
/// their listeners' certificateRefs.
#[derive(Clone, Debug, PartialEq)]
struct SecretGrant {
    /// The namespace of the grant, and of the Secrets it covers.
    namespace: String,
    /// The namespaces of the Gateways it trusts.
    from: HashSet<String>,
    /// The Secrets it covers by name; `None`: all of its namespace.
    names: Option<HashSet<String>>,
}

impl SecretGrant {
    fn of(grant: &ReferenceGrant) -> Option<Self> {
        let namespace = grant.metadata.namespace.clone()?;
        let from: HashSet<String> = grant
            .spec
            .from
            .iter()
            .filter(|f| f.group == GATEWAY_API_GROUP && f.kind == "Gateway")
            .map(|f| f.namespace.clone())
            .collect();
        let to: Vec<&_> = grant
            .spec
            .to
            .iter()
            .filter(|t| t.group.is_empty() && t.kind == "Secret")
            .collect();
        if from.is_empty() || to.is_empty() {
            return None;
        }
        // One entry naming no Secret opens them all.
        let names = to
            .iter()
            .map(|t| t.name.clone())
            .collect::<Option<HashSet<String>>>();
        Some(Self {
            namespace,
            from,
            names,
        })
    }

    fn allows(&self, gateway_ns: &str, secret_ns: &str, secret: &str) -> bool {
        self.namespace == secret_ns
            && self.from.contains(gateway_ns)
            && self.names.as_ref().is_none_or(|n| n.contains(secret))
    }
}

/// A Gateway listener: `(namespace, gateway name, listener name)`.
type ListenerKey = (String, String, String);

/// The ports Sōzune can serve a Gateway listener on, from `config.yaml`: the
/// ones it binds at startup, and those a Gateway may open (`gateway_ports`).
#[derive(Clone, Debug, Default)]
pub struct ServedPorts {
    pub http: u16,
    pub https: u16,
    pub tcp: HashSet<u16>,
    pub udp: HashSet<u16>,
    pub gateway: crate::config::GatewayPortsConfig,
    /// The ports of `gateway` Sōzune could not open, as the proxy reported.
    pub unopened: crate::proxy::backend::UnopenedGatewayPorts,
}

impl ServedPorts {
    pub fn from_config(proxy: &crate::config::ProxyConfig) -> Self {
        Self {
            http: proxy.http.listen_address,
            https: proxy.https.listen_address,
            tcp: proxy.tcp.iter().map(|l| l.listen).collect(),
            udp: proxy.udp.iter().map(|l| l.listen).collect(),
            gateway: proxy.gateway_ports.clone(),
            unopened: Default::default(),
        }
    }

    /// Why a TCP or TLS listener on `port` is not served, if it is not.
    fn tcp_problem(&self, port: i32) -> Option<String> {
        match u16::try_from(port).ok() {
            Some(p) if self.tcp.contains(&p) => None,
            Some(p) if self.gateway.allows_tcp(p) => self
                .unopened
                .tcp
                .get(&p)
                .map(|e| format!("Sōzune could not open port {p}: {e}")),
            _ => Some(format!(
                "port {port} is neither a proxy.tcp listener nor in proxy.gateway_ports.tcp in config.yaml, so routes attached here are not served"
            )),
        }
    }

    /// The UDP twin of [`Self::tcp_problem`].
    fn udp_problem(&self, port: i32) -> Option<String> {
        match u16::try_from(port).ok() {
            Some(p) if self.udp.contains(&p) => None,
            Some(p) if self.gateway.allows_udp(p) => self
                .unopened
                .udp
                .get(&p)
                .map(|e| format!("Sōzune could not open port {p}: {e}")),
            _ => Some(format!(
                "port {port} is neither a proxy.udp listener nor in proxy.gateway_ports.udp in config.yaml, so routes attached here are not served"
            )),
        }
    }
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
    /// Woken when the certificates the accepted Gateways reference may have
    /// changed, for the task handing them to the HTTPS worker.
    certificates: Arc<Notify>,
}

impl GatewayScope {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the ports Sōzune listens on and where Gateway status rewrites
    /// go. Called once, before the watchers start.
    pub fn configure_status(&self, served: ServedPorts, status_tx: mpsc::Sender<StatusWrite>) {
        match self.state.write() {
            Ok(mut g) => {
                g.served = served;
                g.status_tx = Some(status_tx);
            }
            Err(e) => error!("Gateway API: scope lock poisoned: {}", e),
        }
    }

    /// Record the listeners a route attaches to: those of a Gateway sōzune
    /// owns that one of its `parentRefs` selects and that carry its kind
    /// (`listener_ok`). Per the Gateway API spec, attachment depends on the
    /// `parentRefs` alone, not on whether the route itself is accepted. A
    /// Gateway whose count changes gets its status rewritten.
    pub fn record_attachments<P: ParentRef>(
        &self,
        kind: &'static str,
        uid: &str,
        route_namespace: &str,
        route_hostnames: &[String],
        parent_refs: &[P],
        listener_ok: fn(&ListenerInfo) -> bool,
    ) {
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return;
            }
        };
        let mut attached: Vec<ListenerKey> = Vec::new();
        for parent_ref in parent_refs {
            if parent_ref.kind().unwrap_or("Gateway") != "Gateway" {
                continue;
            }
            let group = parent_ref.group().unwrap_or(GATEWAY_API_GROUP);
            if !group.is_empty() && group != GATEWAY_API_GROUP {
                continue;
            }
            let ns = parent_ref
                .namespace()
                .unwrap_or(route_namespace)
                .to_string();
            let name = parent_ref.name().to_string();
            let Some(listeners) = g.gateways.get(&(ns.clone(), name.clone())) else {
                continue;
            };
            for listener in listeners
                .iter()
                .filter(|l| listener_ok(l) && l.admits(&ns, route_namespace, kind))
                // A listener whose hostname admits none of the route's
                // serves none of it.
                .filter(|l| {
                    intersect_hostnames(route_hostnames, std::slice::from_ref(*l)).is_some()
                })
            {
                let name_ok = parent_ref.section_name().is_none_or(|s| s == listener.name);
                let port_ok = parent_ref.port().is_none_or(|p| p == listener.port);
                let key = (ns.clone(), name.clone(), listener.name.clone());
                if name_ok && port_ok && !attached.contains(&key) {
                    attached.push(key);
                }
            }
        }
        Self::store_attachments(&mut g, (kind, uid.to_string()), attached);
    }

    /// Forget the listeners a deleted route was attached to.
    pub fn forget_attachments(&self, kind: &'static str, uid: &str) {
        match self.state.write() {
            Ok(mut g) => Self::store_attachments(&mut g, (kind, uid.to_string()), Vec::new()),
            Err(e) => error!("Gateway API: scope lock poisoned: {}", e),
        }
    }

    /// Forget the attachments of the routes of `kind` that are not in
    /// `uids`, after a relist that did not return them.
    pub fn retain_attachments(&self, kind: &'static str, uids: &HashSet<String>) {
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return;
            }
        };
        let stale: Vec<String> = g
            .attachments
            .keys()
            .filter(|(k, uid)| *k == kind && !uids.contains(uid))
            .map(|(_, uid)| uid.clone())
            .collect();
        for uid in stale {
            Self::store_attachments(&mut g, (kind, uid), Vec::new());
        }
    }

    fn store_attachments(
        g: &mut ScopeState,
        route: (&'static str, String),
        attached: Vec<ListenerKey>,
    ) {
        let previous = if attached.is_empty() {
            g.attachments.remove(&route).unwrap_or_default()
        } else {
            g.attachments
                .insert(route, attached.clone())
                .unwrap_or_default()
        };
        if previous == attached {
            return;
        }
        let gateways: HashSet<(String, String)> = previous
            .iter()
            .chain(attached.iter())
            .map(|(ns, name, _)| (ns.clone(), name.clone()))
            .collect();
        for key in gateways {
            if g.gateways.contains_key(&key)
                && let Some(gateway) = g.gateway_objects.get(&key)
            {
                queue_status_write(
                    g.status_tx.as_ref(),
                    StatusWrite::Gateway(Box::new(gateway.clone())),
                );
            }
        }
    }

    /// Record the ports of `proxy.gateway_ports` the proxy could not open,
    /// and rewrite the status of the Gateways with a listener on a port whose
    /// state changed. Waits for room in the status channel rather than drop a
    /// write: no other event would bring the listener status up to date.
    pub async fn set_unopened_ports(&self, ports: crate::proxy::backend::UnopenedGatewayPorts) {
        let (writes, status_tx) = {
            let mut g = match self.state.write() {
                Ok(g) => g,
                Err(e) => {
                    error!("Gateway API: scope lock poisoned: {}", e);
                    return;
                }
            };
            let changed = |old: &BTreeMap<u16, String>, new: &BTreeMap<u16, String>| {
                old.keys()
                    .chain(new.keys())
                    .filter(|p| old.get(p) != new.get(p))
                    .copied()
                    .collect::<HashSet<u16>>()
            };
            let tcp = changed(&g.served.unopened.tcp, &ports.tcp);
            let udp = changed(&g.served.unopened.udp, &ports.udp);
            g.served.unopened = ports;
            let affected = |listener: &ListenerInfo| {
                let Ok(port) = u16::try_from(listener.port) else {
                    return false;
                };
                match listener.protocol.to_ascii_uppercase().as_str() {
                    "TLS" | "TCP" => tcp.contains(&port),
                    "UDP" => udp.contains(&port),
                    _ => false,
                }
            };
            let writes: Vec<StatusWrite> = g
                .gateway_objects
                .iter()
                .filter(|(key, gateway)| {
                    g.gateways.contains_key(*key) && listeners_of(gateway).iter().any(affected)
                })
                .map(|(_, gateway)| StatusWrite::Gateway(Box::new(gateway.clone())))
                .collect();
            (writes, g.status_tx.clone())
        };
        let Some(status_tx) = status_tx else {
            return;
        };
        for write in writes {
            if status_tx.send(write).await.is_err() {
                return;
            }
        }
    }

    /// Woken when the certificates the accepted Gateways reference may have
    /// changed.
    pub async fn certificates_changed(&self) {
        self.certificates.notified().await
    }

    /// Record what a TLS Secret holds, and rewrite the status of the Gateways
    /// referencing it.
    pub fn upsert_tls_secret(
        &self,
        key: (String, String),
        certificate: Result<Arc<SecretCertificate>, String>,
    ) {
        self.update_tls_secrets(|secrets| {
            if secrets.get(&key) == Some(&certificate) {
                return Vec::new();
            }
            secrets.insert(key.clone(), certificate);
            vec![key]
        });
    }

    pub fn remove_tls_secret(&self, key: &(String, String)) {
        self.update_tls_secrets(|secrets| {
            secrets
                .remove(key)
                .map(|_| vec![key.clone()])
                .unwrap_or_default()
        });
    }

    /// Mark unusable every TLS Secret whose certificate expired by `now`.
    pub fn expire_tls_secrets(&self, now: i64) {
        self.update_tls_secrets(|secrets| {
            let expired: Vec<(String, String)> = secrets
                .iter()
                .filter(|(_, c)| c.as_ref().is_ok_and(|c| c.not_after < now))
                .map(|(key, _)| key.clone())
                .collect();
            for key in &expired {
                secrets.insert(key.clone(), Err("the certificate has expired".to_string()));
            }
            expired
        });
    }

    /// Drop every TLS Secret of `namespace` (`None`: of any) not in `kept`:
    /// those a relist of it did not bring back.
    pub fn retain_tls_secrets(&self, kept: &HashSet<(String, String)>, namespace: Option<&str>) {
        self.update_tls_secrets(|secrets| {
            let gone: Vec<(String, String)> = secrets
                .keys()
                .filter(|(ns, _)| namespace.is_none_or(|n| n == ns))
                .filter(|key| !kept.contains(*key))
                .cloned()
                .collect();
            for key in &gone {
                secrets.remove(key);
            }
            gone
        });
    }

    /// Apply `update` to the TLS Secrets. It returns the Secrets it changed:
    /// the Gateways referencing one get their status rewritten, and the
    /// certificates are handed over again.
    fn update_tls_secrets(
        &self,
        update: impl FnOnce(
            &mut HashMap<(String, String), Result<Arc<SecretCertificate>, String>>,
        ) -> Vec<(String, String)>,
    ) {
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return;
            }
        };
        let changed = update(&mut g.tls_secrets);
        if changed.is_empty() {
            return;
        }
        for (key, gateway) in &g.gateway_objects {
            if g.gateways.contains_key(key)
                && changed
                    .iter()
                    .any(|secret| references_secret(gateway, secret))
            {
                queue_status_write(
                    g.status_tx.as_ref(),
                    StatusWrite::Gateway(Box::new(gateway.clone())),
                );
            }
        }
        drop(g);
        // Routes too: an HTTPS listener serves them only with a certificate.
        self.fire_if(true);
    }

    /// Whether the `HTTPS` listener `listener` of Gateway `ns/name` has a
    /// certificate it can serve. Without one, its routes are not served
    /// over HTTPS: there is nothing to complete a handshake with.
    fn listener_has_certificate(&self, ns: &str, name: &str, listener: &str) -> bool {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return false;
            }
        };
        g.gateway_objects
            .get(&(ns.to_string(), name.to_string()))
            .and_then(|gw| gw.spec.listeners.iter().find(|l| l.name == listener))
            .is_some_and(|l| {
                !listener_certificates(&g.tls_secrets, &g.secret_grants, ns, l)
                    .0
                    .is_empty()
            })
    }

    /// Record the TLS Secrets an Ingress names, none once it is gone.
    pub fn set_ingress_secrets(&self, ingress: &str, secrets: Vec<(String, String)>) {
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return;
            }
        };
        let changed = if secrets.is_empty() {
            g.ingress_secrets.remove(ingress).is_some()
        } else {
            g.ingress_secrets
                .insert(ingress.to_string(), secrets.clone())
                != Some(secrets)
        };
        drop(g);
        if changed {
            self.certificates.notify_one();
        }
    }

    /// The certificates the `HTTPS` listeners of the accepted Gateways, and
    /// the Ingresses, reference and can use.
    pub fn referenced_certificates(&self) -> Vec<Arc<SecretCertificate>> {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return Vec::new();
            }
        };
        g.gateway_objects
            .iter()
            .filter(|(key, _)| g.gateways.contains_key(*key))
            .flat_map(|((ns, _), gateway)| {
                gateway
                    .spec
                    .listeners
                    .iter()
                    .filter(|l| serves_https(l))
                    .flat_map(|l| listener_certificates(&g.tls_secrets, &g.secret_grants, ns, l).0)
                    .collect::<Vec<_>>()
            })
            .chain(
                g.ingress_secrets
                    .values()
                    .flatten()
                    .filter_map(|key| g.tls_secrets.get(key)?.as_ref().ok().cloned()),
            )
            .collect()
    }

    /// The `status.listeners[]` sōzune reports on an accepted Gateway: per
    /// listener, the route kinds it carries, how many routes attach to it,
    /// and whether Sōzune serves its port.
    pub fn listener_statuses(
        &self,
        gateway: &Gateway,
    ) -> Vec<gateway_api::apis::standard::gateways::GatewayStatusListeners> {
        let ns = gateway.metadata.namespace.as_deref().unwrap_or("default");
        let name = gateway.metadata.name.as_deref().unwrap_or_default();
        let g = match self.state.read() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return Vec::new();
            }
        };
        listeners_of(gateway)
            .iter()
            .map(|listener| {
                let key = (ns.to_string(), name.to_string(), listener.name.clone());
                let attached = g
                    .attachments
                    .values()
                    .filter(|keys| keys.contains(&key))
                    .count();
                let certificates = gateway
                    .spec
                    .listeners
                    .iter()
                    .find(|l| l.name == listener.name && serves_https(l))
                    .and_then(|l| listener_certificates(&g.tls_secrets, &g.secret_grants, ns, l).1);
                build_listener_status(gateway, listener, &g.served, attached, certificates)
            })
            .collect()
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
        // An HTTPRoute is served on the configured HTTP listener whatever port
        // the Gateway declares, but only through an HTTP listener
        // whose `allowedRoutes` admits it: another protocol's listener would
        // let it past the restrictions of the HTTP ones.
        self.accepts_parent_ref_where(
            route_namespace,
            parent_ref,
            "HTTPRoute",
            Some(Self::listener_serves_http),
        )
    }

    /// Why a Gateway we own refuses `parent_ref`, for the route's status:
    /// `NoMatchingParent` when its `sectionName`/`port` selects no listener,
    /// `NotAllowedByListeners` when the listeners it selects carry no
    /// `route_kind` (per `listener_ok`) or none admits the route's namespace.
    /// `None` when the parent is not ours, or accepts the route.
    fn parent_refusal<P: ParentRef>(
        &self,
        route_namespace: &str,
        parent_ref: &P,
        route_kind: &str,
        listener_ok: fn(&ListenerInfo) -> bool,
    ) -> Option<&'static str> {
        if parent_ref.kind().unwrap_or("Gateway") != "Gateway" {
            return None;
        }
        let group = parent_ref.group().unwrap_or(GATEWAY_API_GROUP);
        if !group.is_empty() && group != GATEWAY_API_GROUP {
            return None;
        }
        let ns = parent_ref.namespace().unwrap_or(route_namespace);
        let key = (ns.to_string(), parent_ref.name().to_string());
        let g = match self.state.read() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return None;
            }
        };
        let listeners = g.gateways.get(&key)?;
        let admitted: Vec<ListenerInfo> = listeners
            .iter()
            .filter(|l| listener_ok(l) && l.admits(ns, route_namespace, route_kind))
            .cloned()
            .collect();
        if !admitted.is_empty() && parent_ref_selects_listener(parent_ref, &admitted) {
            None
        } else if listeners.is_empty() || !parent_ref_selects_listener(parent_ref, listeners) {
            Some(REASON_NO_MATCHING_PARENT)
        } else {
            Some(REASON_NOT_ALLOWED_BY_LISTENERS)
        }
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
        route_kind: &str,
        listener_ok: Option<impl Fn(&ListenerInfo) -> bool>,
    ) -> bool {
        if parent_ref.kind().unwrap_or("Gateway") != "Gateway" {
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
                Some(listeners) => {
                    let eligible: Vec<ListenerInfo> = listeners
                        .iter()
                        .filter(|l| l.admits(ns, route_namespace, route_kind))
                        .filter(|l| listener_ok.as_ref().is_none_or(|pred| pred(l)))
                        .cloned()
                        .collect();
                    !eligible.is_empty() && parent_ref_selects_listener(parent_ref, &eligible)
                }
                None => false,
            },
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                false
            }
        }
    }

    /// True iff this listener can carry an HTTPRoute: protocol `HTTP`, or
    /// `HTTPS` terminating TLS.
    pub(crate) fn listener_serves_http(l: &ListenerInfo) -> bool {
        Self::listener_is_plain_http(l) || Self::listener_serves_https(l)
    }

    /// True iff this listener serves its routes over plain HTTP.
    pub(crate) fn listener_is_plain_http(l: &ListenerInfo) -> bool {
        l.protocol.eq_ignore_ascii_case("HTTP")
    }

    /// True iff this listener serves its routes over HTTPS: protocol `HTTPS`
    /// with `tls.mode: Terminate`, the default. `Passthrough` belongs on a
    /// `TLS` listener.
    pub(crate) fn listener_serves_https(l: &ListenerInfo) -> bool {
        l.protocol.eq_ignore_ascii_case("HTTPS")
            && matches!(l.tls_mode, None | Some(GatewayListenersTlsMode::Terminate))
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
            "TLSRoute",
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
        self.accepts_parent_ref_where(
            route_namespace,
            parent_ref,
            "TCPRoute",
            Some(Self::listener_serves_tcp),
        )
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
            let Some(listeners) = self.gateway_listeners(ns, &p.name, route_ns, "TCPRoute") else {
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

    /// True iff this listener can carry a UDPRoute: protocol `UDP`.
    fn listener_serves_udp(l: &ListenerInfo) -> bool {
        l.protocol.eq_ignore_ascii_case("UDP")
    }

    /// True iff `parent_ref` binds this UDPRoute to a `UDP` listener we own.
    fn accepts_udp_parent_ref(
        &self,
        route_namespace: &str,
        parent_ref: &UDPRouteParentRefs,
    ) -> bool {
        self.accepts_parent_ref_where(
            route_namespace,
            parent_ref,
            "UDPRoute",
            Some(Self::listener_serves_udp),
        )
    }

    /// True iff at least one `parentRef` binds this UDPRoute to a listener we
    /// can serve.
    pub fn accepts_udp_route(&self, route: &UDPRoute) -> bool {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let Some(refs) = route.spec.parent_refs.as_ref() else {
            return false;
        };
        refs.iter()
            .any(|p| self.accepts_udp_parent_ref(route_ns, p))
    }

    /// The Gateway listener ports this UDPRoute binds to, resolved to
    /// `proxy.udp` listeners by the caller. Like TCPRoute, no hostnames — a
    /// datagram listener forwards the whole port.
    fn effective_udp_ports(&self, route: &UDPRoute) -> std::collections::BTreeSet<i32> {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let mut ports = std::collections::BTreeSet::new();
        let Some(refs) = route.spec.parent_refs.as_ref() else {
            return ports;
        };
        for p in refs
            .iter()
            .filter(|p| self.accepts_udp_parent_ref(route_ns, p))
        {
            let ns = p.namespace.as_deref().unwrap_or(route_ns);
            let Some(listeners) = self.gateway_listeners(ns, &p.name, route_ns, "UDPRoute") else {
                continue;
            };
            for listener in listeners.into_iter().filter(Self::listener_serves_udp) {
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
            let Some(listeners) = self.gateway_listeners(ns, &p.name, route_ns, "TLSRoute") else {
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
    fn gateway_listeners(
        &self,
        ns: &str,
        name: &str,
        route_ns: &str,
        kind: &str,
    ) -> Option<Vec<ListenerInfo>> {
        match self.state.read() {
            Ok(g) => g
                .gateways
                .get(&(ns.to_string(), name.to_string()))
                .map(|listeners| {
                    listeners
                        .iter()
                        .filter(|l| l.admits(ns, route_ns, kind))
                        .cloned()
                        .collect()
                }),
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
    /// Only the listeners `listener_ok` takes count: those serving HTTP, or
    /// those serving HTTPS.
    ///
    /// Returns `Some(hostnames)` (deduplicated, order-stable; an empty vec
    /// means "all hosts", exactly like an empty `spec.hostnames`), or `None`
    /// when the route binds no such listener, or when every one it binds
    /// constrains hostnames and none of them overlaps the route — the route
    /// resolves to nothing there. Falls back to the route's own hostnames
    /// when no bound listener constrains hostnames.
    fn effective_hostnames_for_route(
        &self,
        route: &HTTPRoute,
        listener_ok: fn(&ListenerInfo) -> bool,
    ) -> Option<Vec<String>> {
        let route_hostnames = route.spec.hostnames.clone().unwrap_or_default();
        if route.spec.parent_refs.is_none() {
            return Some(route_hostnames);
        }

        let mut out: Vec<String> = Vec::new();
        let mut any_overlap = false;
        for selected in self.bound_listeners(route, listener_ok) {
            if let Some(hs) = intersect_hostnames(&route_hostnames, &selected) {
                any_overlap = true;
                for h in hs {
                    if !out.contains(&h) {
                        out.push(h);
                    }
                }
            }
        }
        any_overlap.then_some(out)
    }

    /// The port to redirect plain HTTP requests to, for a route only served
    /// over HTTPS: the port of the `HTTPS` listeners it binds, when they all
    /// share one other than 443. `None` keeps the default port.
    fn https_redirect_port(&self, route: &HTTPRoute) -> Option<u16> {
        let route_hostnames = route.spec.hostnames.clone().unwrap_or_default();
        let ports: HashSet<i32> = self
            .bound_listeners(route, Self::listener_serves_https)
            .into_iter()
            .flatten()
            .filter(|l| intersect_hostnames(&route_hostnames, std::slice::from_ref(l)).is_some())
            .map(|l| l.port)
            .collect();
        match ports.into_iter().collect::<Vec<_>>()[..] {
            [port] if port != 443 => u16::try_from(port).ok(),
            _ => None,
        }
    }

    /// The listeners each accepted `parentRef` of the route binds among those
    /// `listener_ok` takes, one list per parentRef that binds any.
    fn bound_listeners(
        &self,
        route: &HTTPRoute,
        listener_ok: fn(&ListenerInfo) -> bool,
    ) -> Vec<Vec<ListenerInfo>> {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let Some(refs) = route.spec.parent_refs.as_ref() else {
            return Vec::new();
        };
        refs.iter()
            .filter(|p| self.accepts_parent_ref(route_ns, *p))
            .filter_map(|p| {
                let ns = p.namespace.as_deref().unwrap_or(route_ns);
                let mut listeners = self.gateway_listeners(ns, &p.name, route_ns, "HTTPRoute")?;
                listeners.retain(listener_ok);
                listeners.retain(|l| {
                    !Self::listener_serves_https(l)
                        || self.listener_has_certificate(ns, &p.name, &l.name)
                });
                // Restrict to the listener(s) this parentRef selects, so a
                // sectionName/port ref only inherits its own listener's
                // hostname.
                listeners.retain(|l| {
                    let name_ok = p.section_name.as_deref().is_none_or(|s| s == l.name);
                    let port_ok = p.port.is_none_or(|port| port == l.port);
                    name_ok && port_ok
                });
                (!listeners.is_empty()).then_some(listeners)
            })
            .collect()
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
            self.certificates.notify_one();
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
        let tls_of =
            |gw: &Gateway| -> Vec<_> { gw.spec.listeners.iter().map(|l| l.tls.clone()).collect() };
        // The certificateRefs decide which HTTPS listeners serve their routes,
        // and they are not in the listener list compared below.
        let tls_changed = accepted
            && g.gateway_objects
                .get(&key)
                .is_none_or(|old| tls_of(old) != tls_of(gateway));
        if accepted {
            g.gateway_objects.insert(key.clone(), gateway.clone());
        } else {
            g.gateway_objects.remove(&key);
        }
        let changed = tls_changed
            | match (accepted, g.gateways.get(&key)) {
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
        let key = (namespace.to_string(), name.to_string());
        g.gateway_objects.remove(&key);
        let removed = g.gateways.remove(&key).is_some();
        drop(g);
        self.certificates.notify_one();
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
        // authorising e.g. HTTPRoute→Service also lets a TLSRoute/TCPRoute/
        // UDPRoute in the same namespace reach that target. This is slightly
        // more permissive than the spec (a grant names one `from.kind`);
        // tightening it to a per-kind key is a separate hardening step.
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

    /// Record what a ReferenceGrant lets Gateways reference among Secrets,
    /// `None` once it is gone or covers no Secret. A change rewrites the
    /// status of the Gateways naming a Secret of its namespace and hands the
    /// certificates over again.
    fn update_secret_grant(&self, grant: &ReferenceGrant, secret_grant: Option<SecretGrant>) {
        let (Some(ns), Some(name)) = (
            grant.metadata.namespace.clone(),
            grant.metadata.name.clone(),
        ) else {
            return;
        };
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return;
            }
        };
        let key = (ns.clone(), name);
        let changed = match secret_grant {
            Some(sg) => g.secret_grants.insert(key, sg.clone()).as_ref() != Some(&sg),
            None => g.secret_grants.remove(&key).is_some(),
        };
        if !changed {
            return;
        }
        for (key, gateway) in &g.gateway_objects {
            if g.gateways.contains_key(key) && references_secret_in(gateway, &ns) {
                queue_status_write(
                    g.status_tx.as_ref(),
                    StatusWrite::Gateway(Box::new(gateway.clone())),
                );
            }
        }
        drop(g);
        self.fire_if(true);
    }

    /// Keep only the ReferenceGrants a relist brought back: one deleted while
    /// the watch was down sends no `Delete`, and must not keep authorising
    /// anything.
    pub fn retain_reference_grants(&self, kept: &[ReferenceGrant]) {
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return;
            }
        };
        let pairs: HashSet<(String, String)> = kept
            .iter()
            .filter_map(|grant| {
                let to_ns = grant.metadata.namespace.clone()?;
                Some(
                    trusted_route_from_namespaces(grant)
                        .into_iter()
                        .map(move |from| (from, to_ns.clone())),
                )
            })
            .flatten()
            .collect();
        let keys: HashSet<(String, String)> = kept
            .iter()
            .filter_map(|grant| {
                Some((
                    grant.metadata.namespace.clone()?,
                    grant.metadata.name.clone()?,
                ))
            })
            .collect();
        let before = g.secret_grants.len();
        g.secret_grants.retain(|key, _| keys.contains(key));
        let changed = g.reference_grants != pairs || g.secret_grants.len() != before;
        g.reference_grants = pairs;
        if changed {
            for gateway in g.gateway_objects.values() {
                queue_status_write(
                    g.status_tx.as_ref(),
                    StatusWrite::Gateway(Box::new(gateway.clone())),
                );
            }
        }
        drop(g);
        self.fire_if(changed);
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
        self.update_secret_grant(grant, SecretGrant::of(grant));
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
        self.update_secret_grant(grant, None);
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
                && matches!(
                    f.kind.as_str(),
                    "HTTPRoute" | "TLSRoute" | "TCPRoute" | "UDPRoute"
                )
        })
        .map(|f| f.namespace.clone())
        .collect()
}

/// Extract the [`ListenerInfo`] slice sōzune tracks from a Gateway's
/// `spec.listeners[]`. Only `name`, `port` and `hostname` are kept — the
/// data needed for `parentRef` listener selection and hostname narrowing.
/// Whether a listener of the Gateway spec terminates TLS for HTTPRoutes,
/// as [`GatewayScope::listener_serves_https`] says of its [`ListenerInfo`].
fn serves_https(l: &GatewayListeners) -> bool {
    l.protocol.eq_ignore_ascii_case("HTTPS")
        && matches!(
            l.tls.as_ref().and_then(|t| t.mode.as_ref()),
            None | Some(GatewayListenersTlsMode::Terminate)
        )
}

/// The TLS Secrets a listener's `certificateRefs` name, as `(namespace,
/// name)`, with the reference itself.
fn certificate_refs<'a>(
    gateway_ns: &'a str,
    l: &'a GatewayListeners,
) -> impl Iterator<Item = ((String, String), &'a GatewayListenersTlsCertificateRefs)> + 'a {
    l.tls
        .iter()
        .flat_map(|t| t.certificate_refs.iter().flatten())
        .map(move |r| {
            let ns = r.namespace.as_deref().unwrap_or(gateway_ns);
            ((ns.to_string(), r.name.clone()), r)
        })
}

/// Whether one of the Gateway's `HTTPS` listeners names a Secret of
/// `namespace`.
fn references_secret_in(gateway: &Gateway, namespace: &str) -> bool {
    let ns = gateway.metadata.namespace.as_deref().unwrap_or("default");
    gateway
        .spec
        .listeners
        .iter()
        .filter(|l| serves_https(l))
        .any(|l| certificate_refs(ns, l).any(|((secret_ns, _), _)| secret_ns == namespace))
}

/// Whether one of the Gateway's `HTTPS` listeners references `secret`.
fn references_secret(gateway: &Gateway, secret: &(String, String)) -> bool {
    let ns = gateway.metadata.namespace.as_deref().unwrap_or("default");
    gateway
        .spec
        .listeners
        .iter()
        .filter(|l| serves_https(l))
        .any(|l| certificate_refs(ns, l).any(|(key, _)| &key == secret))
}

/// The certificates an `HTTPS` listener's `certificateRefs` resolve to, and
/// the first reason one does not, as a `ResolvedRefs` reason and message.
/// The references that resolve are served even when another does not.
fn listener_certificates(
    secrets: &HashMap<(String, String), Result<Arc<SecretCertificate>, String>>,
    grants: &HashMap<(String, String), SecretGrant>,
    gateway_ns: &str,
    l: &GatewayListeners,
) -> (Vec<Arc<SecretCertificate>>, Option<(&'static str, String)>) {
    let mut certificates = Vec::new();
    let mut problem = None;
    let mut refs = certificate_refs(gateway_ns, l).peekable();
    if refs.peek().is_none() {
        problem = Some((
            REASON_INVALID_CERTIFICATE_REF,
            "an HTTPS listener needs a certificateRefs entry naming a kubernetes.io/tls Secret"
                .to_string(),
        ));
    }
    for ((ns, name), r) in refs {
        let found = if r.group.as_deref().is_some_and(|g| !g.is_empty())
            || r.kind.as_deref().is_some_and(|k| k != "Secret")
        {
            Err((
                REASON_INVALID_CERTIFICATE_REF,
                format!("certificateRef {name} is not a core Secret"),
            ))
        } else if ns != gateway_ns && !grants.values().any(|g| g.allows(gateway_ns, &ns, &name)) {
            Err((
                REASON_REF_NOT_PERMITTED,
                format!(
                    "certificateRef {ns}/{name} is in another namespace, and no ReferenceGrant there lets Gateways of {gateway_ns} reference it"
                ),
            ))
        } else {
            match secrets.get(&(ns.clone(), name.clone())) {
                // Sōzu picks a certificate by SNI: one that does not cover
                // the listener's hostname would never be presented for it.
                Some(Ok(certificate))
                    if l.hostname
                        .as_deref()
                        .is_some_and(|h| !crate::manual_certs::covered(&certificate.names, h)) =>
                {
                    Err((
                        REASON_INVALID_CERTIFICATE_REF,
                        format!(
                            "the certificate of Secret {ns}/{name} does not cover hostname {}",
                            l.hostname.as_deref().unwrap_or_default()
                        ),
                    ))
                }
                Some(Ok(certificate)) => Ok(Arc::clone(certificate)),
                Some(Err(e)) => Err((
                    REASON_INVALID_CERTIFICATE_REF,
                    format!("Secret {ns}/{name} cannot be used: {e}"),
                )),
                None => Err((
                    REASON_INVALID_CERTIFICATE_REF,
                    format!(
                        "Secret {ns}/{name} does not exist or is not of type kubernetes.io/tls"
                    ),
                )),
            }
        };
        match found {
            Ok(certificate) => certificates.push(certificate),
            Err(e) => {
                problem.get_or_insert(e);
            }
        }
    }
    (certificates, problem)
}

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
            allowed_namespaces: match l
                .allowed_routes
                .as_ref()
                .and_then(|a| a.namespaces.as_ref())
                .and_then(|n| n.from.as_ref())
            {
                None | Some(GatewayListenersAllowedRoutesNamespacesFrom::Same) => {
                    AllowedNamespaces::Same
                }
                Some(GatewayListenersAllowedRoutesNamespacesFrom::All) => AllowedNamespaces::All,
                Some(GatewayListenersAllowedRoutesNamespacesFrom::Selector) => {
                    AllowedNamespaces::Selector
                }
            },
            allowed_kinds: l
                .allowed_routes
                .as_ref()
                .and_then(|a| a.kinds.as_ref())
                .filter(|kinds| !kinds.is_empty())
                .map(|kinds| {
                    // A kind of another group is no route Sōzune serves:
                    // dropping it can leave the list empty, which admits
                    // nothing rather than falling back to the protocol.
                    kinds
                        .iter()
                        .filter(|k| k.group.as_deref().is_none_or(|g| g == GATEWAY_API_GROUP))
                        .map(|k| k.kind.clone())
                        .collect()
                }),
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
    // Keep what each route hostname shares with each listener hostname: the
    // narrower of the two, so `*.example.com` on a `web.example.com` listener
    // serves `web.example.com` alone. Of two compatible names, the longer is
    // the narrower.
    let mut kept: Vec<String> = Vec::new();
    for rh in route_hostnames {
        for lh in &listener_hosts {
            if !hostnames_compatible(rh, lh) {
                continue;
            }
            let narrower = if lh.len() > rh.len() {
                *lh
            } else {
                rh.as_str()
            };
            if !kept.iter().any(|k| k == narrower) {
                kept.push(narrower.to_string());
            }
        }
    }
    if kept.is_empty() { None } else { Some(kept) }
}

/// Whether the Gateway API hostname `pattern` takes every host `host` does:
/// the same name, or a `*.` wildcard over it.
fn hostname_covers(pattern: &str, host: &str) -> bool {
    pattern == host
        || pattern
            .strip_prefix("*.")
            .is_some_and(|suffix| host.strip_suffix(suffix).is_some_and(|p| p.ends_with('.')))
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
    // The routes the current relist returned; the others were deleted while
    // the watcher was away.
    let mut relisted: Option<HashSet<String>> = None;

    loop {
        let changed = tokio::select! {
            event = stream.next() => match event {
                Some(Ok(Event::Apply(route))) | Some(Ok(Event::InitApply(route))) => {
                    if let (Some(uids), Some(uid)) = (relisted.as_mut(), route.metadata.uid.as_deref()) {
                        uids.insert(uid.to_string());
                    }
                    log_route("apply", &route);
                    apply_route(&route, &storage, &index, resolver.as_ref(), &scope, Some(&status_tx))
                }
                Some(Ok(Event::Delete(route))) => {
                    log_route("delete", &route);
                    if let Some(uid) = route.metadata.uid.as_deref() {
                        scope.forget_attachments("HTTPRoute", uid);
                    }
                    delete_route(&route, &storage, &index)
                }
                Some(Ok(Event::Init)) => {
                    debug!("Gateway API: HTTPRoute init");
                    relisted = Some(HashSet::new());
                    false
                }
                Some(Ok(Event::InitDone)) => {
                    debug!("Gateway API: HTTPRoute init done");
                    match relisted.take() {
                        Some(uids) => drop_routes_not_relisted(
                            "HTTPRoute",
                            &uids,
                            &index,
                            |t: &TrackedRoute| t.entrypoint_ids.as_slice(),
                            &storage,
                            &scope,
                        ),
                        None => false,
                    }
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

    // The grants a relist brings back: those it does not are gone.
    let mut relisted: Vec<ReferenceGrant> = Vec::new();
    while let Some(event) = stream.next().await {
        match event {
            Ok(Event::InitApply(grant)) => {
                scope.upsert_reference_grant(&grant);
                relisted.push(grant);
            }
            Ok(Event::Apply(grant)) => {
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
            Ok(Event::Init) => relisted.clear(),
            Ok(Event::InitDone) => scope.retain_reference_grants(&std::mem::take(&mut relisted)),
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

const REASON_PORT_UNAVAILABLE: &str = "PortUnavailable";
const REASON_UNSUPPORTED_PROTOCOL: &str = "UnsupportedProtocol";
const REASON_INVALID: &str = "Invalid";
const REASON_INVALID_ROUTE_KINDS: &str = "InvalidRouteKinds";
const REASON_INVALID_CERTIFICATE_REF: &str = "InvalidCertificateRef";
const REASON_REF_NOT_PERMITTED: &str = "RefNotPermitted";

/// The status of one Gateway listener, as Sōzune routes it. An HTTP listener
/// is served whatever its port: its routes go through Sōzune's HTTP port, and
/// the message says which. An HTTPS one is not served: a Gateway's routes are
/// installed without TLS. A TLS, TCP or UDP listener is
/// served only on a port a `proxy.tcp` / `proxy.udp` entry listens on or
/// `proxy.gateway_ports` lists, as its routes are: any other port is reported
/// `Accepted=False` (`PortUnavailable`) and `Programmed=False`, with the
/// setting to change.
fn build_listener_status(
    gateway: &Gateway,
    listener: &ListenerInfo,
    served: &ServedPorts,
    attached_routes: usize,
    certificates: Option<(&'static str, String)>,
) -> gateway_api::apis::standard::gateways::GatewayStatusListeners {
    use gateway_api::apis::standard::gateways::{
        GatewayStatusListeners, GatewayStatusListenersSupportedKinds,
    };
    let port = u16::try_from(listener.port).ok();
    let protocol = listener.protocol.to_ascii_uppercase();
    let (kind, problem) = match protocol.as_str() {
        // HTTP routing does not depend on the listener's port: every HTTP
        // route is served on Sōzune's HTTP port, which a Service commonly
        // maps the listener's port to. So an HTTP listener is served on any
        // port, and its status says where.
        "HTTP" => (Some("HTTPRoute"), None),
        // Likewise on Sōzune's HTTPS port, when the listener terminates TLS.
        "HTTPS" if GatewayScope::listener_serves_https(listener) => (Some("HTTPRoute"), None),
        // A TLS listener carries TLSRoutes in Passthrough mode only.
        "TLS" if !GatewayScope::listener_serves_tls_passthrough(listener) => (None, None),
        "TLS" | "TCP" => (
            Some(if protocol == "TLS" {
                "TLSRoute"
            } else {
                "TCPRoute"
            }),
            served.tcp_problem(listener.port),
        ),
        "UDP" => (Some("UDPRoute"), served.udp_problem(listener.port)),
        _ => (None, None),
    };

    let now = Time(k8s_openapi::chrono::Utc::now());
    let generation = gateway.metadata.generation;
    let condition = |type_: &str, ok: bool, reason: &str, message: String| Condition {
        type_: type_.to_string(),
        status: if ok { "True" } else { "False" }.to_string(),
        reason: reason.to_string(),
        message,
        last_transition_time: now.clone(),
        observed_generation: generation,
    };
    let mut conditions = match (kind, problem) {
        (None, _) => {
            let message = if protocol == "TLS" {
                "TLS listeners are served in Passthrough mode only".to_string()
            } else if protocol == "HTTPS" {
                "HTTPS listeners terminate TLS: Passthrough belongs on a TLS listener".to_string()
            } else {
                format!(
                    "protocol {} is not supported: use HTTP, HTTPS, TLS, TCP or UDP",
                    listener.protocol
                )
            };
            vec![
                condition(
                    CONDITION_TYPE_ACCEPTED,
                    false,
                    REASON_UNSUPPORTED_PROTOCOL,
                    message.clone(),
                ),
                condition(CONDITION_TYPE_PROGRAMMED, false, REASON_INVALID, message),
            ]
        }
        (Some(_), Some(message)) => vec![
            condition(
                CONDITION_TYPE_ACCEPTED,
                false,
                REASON_PORT_UNAVAILABLE,
                message.clone(),
            ),
            condition(CONDITION_TYPE_PROGRAMMED, false, REASON_INVALID, message),
        ],
        (Some(_), None) => {
            let served_on = match protocol.as_str() {
                "HTTP" => served.http,
                "HTTPS" => served.https,
                _ => port.unwrap_or_default(),
            };
            let programmed = if port == Some(served_on) {
                format!("Sōzune serves port {served_on}")
            } else {
                format!(
                    "Sōzune serves this listener's routes on its own port {served_on}; map port {} to it",
                    listener.port
                )
            };
            vec![
                condition(
                    CONDITION_TYPE_ACCEPTED,
                    true,
                    REASON_ACCEPTED,
                    "Listener accepted by sōzune".to_string(),
                ),
                condition(
                    CONDITION_TYPE_PROGRAMMED,
                    true,
                    REASON_PROGRAMMED,
                    programmed,
                ),
            ]
        }
    };

    // `allowedRoutes.kinds` can only narrow what the protocol carries. A kind
    // it lists that the listener cannot carry is reported, and a listener
    // left with no kind is not programmed: no route would attach.
    let protocol_kind = kind;
    let kind = protocol_kind.filter(|kind| {
        listener
            .allowed_kinds
            .as_ref()
            .is_none_or(|kinds| kinds.iter().any(|k| k == kind))
    });
    let kinds_problem = listener
        .allowed_kinds
        .as_ref()
        .filter(|_| protocol_kind.is_some())
        .and_then(|listed| {
            let invalid: Vec<&str> = listed
                .iter()
                .map(String::as_str)
                .filter(|k| Some(*k) != kind)
                .collect();
            if kind.is_some() && invalid.is_empty() {
                None
            } else if invalid.is_empty() {
                Some(
                    "allowedRoutes.kinds lists no route kind of the gateway.networking.k8s.io group"
                        .to_string(),
                )
            } else {
                Some(format!(
                    "a {} listener cannot carry {}",
                    protocol,
                    invalid.join(", ")
                ))
            }
        });
    if kind.is_none()
        && let Some(message) = &kinds_problem
    {
        for c in conditions
            .iter_mut()
            .filter(|c| c.type_ == CONDITION_TYPE_PROGRAMMED)
        {
            c.status = "False".to_string();
            c.reason = REASON_INVALID.to_string();
            c.message = message.clone();
        }
    }
    // A certificateRef that does not resolve leaves the listener without the
    // certificate it was given: not programmed, as the spec has it.
    if kinds_problem.is_none()
        && let Some((_, message)) = &certificates
    {
        for c in conditions
            .iter_mut()
            .filter(|c| c.type_ == CONDITION_TYPE_PROGRAMMED && c.status == "True")
        {
            c.status = "False".to_string();
            c.reason = REASON_INVALID.to_string();
            c.message = message.clone();
        }
    }
    // Always reported, so fixing the kinds clears a previous failure.
    conditions.push(match (kinds_problem, certificates) {
        (Some(message), _) => condition(
            CONDITION_TYPE_RESOLVED_REFS,
            false,
            REASON_INVALID_ROUTE_KINDS,
            message,
        ),
        (None, Some((reason, message))) => {
            condition(CONDITION_TYPE_RESOLVED_REFS, false, reason, message)
        }
        (None, None) => condition(
            CONDITION_TYPE_RESOLVED_REFS,
            true,
            REASON_RESOLVED_REFS,
            "Listener references resolved".to_string(),
        ),
    });

    GatewayStatusListeners {
        attached_routes: i32::try_from(attached_routes).unwrap_or(i32::MAX),
        conditions,
        name: listener.name.clone(),
        supported_kinds: kind
            .map(|kind| GatewayStatusListenersSupportedKinds {
                group: Some(GATEWAY_API_GROUP.to_string()),
                kind: kind.to_string(),
            })
            .into_iter()
            .collect(),
    }
}

/// Merge freshly built listener statuses with the ones already on the
/// Gateway: a listener whose conditions did not change keeps its previous
/// `lastTransitionTime`. Returns the listeners to write and whether anything
/// sōzune reports changed.
fn merge_listener_statuses(
    existing: Option<&[gateway_api::apis::standard::gateways::GatewayStatusListeners]>,
    ours: Vec<gateway_api::apis::standard::gateways::GatewayStatusListeners>,
) -> (
    Vec<gateway_api::apis::standard::gateways::GatewayStatusListeners>,
    bool,
) {
    let existing = existing.unwrap_or_default();
    let mut changed = existing.len() != ours.len();
    let merged = ours
        .into_iter()
        .map(|mut ours| {
            match existing.iter().find(|e| e.name == ours.name) {
                Some(prev) => {
                    let (conditions, conditions_changed) =
                        merge_conditions(Some(&prev.conditions), ours.conditions.clone());
                    ours.conditions = conditions;
                    changed |= conditions_changed
                        || prev.attached_routes != ours.attached_routes
                        || prev.supported_kinds.len() != ours.supported_kinds.len()
                        || prev
                            .supported_kinds
                            .iter()
                            .zip(&ours.supported_kinds)
                            .any(|(a, b)| a.kind != b.kind || a.group != b.group);
                }
                None => changed = true,
            }
            ours
        })
        .collect();
    (merged, changed)
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
    // `lastTransitionTime` moves only when the status does: a new reason,
    // message or generation is not a transition.
    merged.extend(ours.iter().map(|our| {
        match existing
            .iter()
            .find(|c| c.type_ == our.type_ && c.status == our.status)
        {
            Some(prev) => Condition {
                last_transition_time: prev.last_transition_time.clone(),
                ..our.clone()
            },
            None => our.clone(),
        }
    }));

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
pub async fn run_gateway_status_writer(
    client: Client,
    scope: GatewayScope,
    mut rx: mpsc::Receiver<StatusWrite>,
) {
    info!("Gateway API: Gateway/GatewayClass status writer started");
    while let Some(msg) = rx.recv().await {
        match msg {
            StatusWrite::Gateway(gw) => patch_gateway_status(&client, &scope, &gw).await,
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

/// Patch the `conditions[]` and `listeners[]` sōzune owns onto a Gateway's
/// status. A Gateway reaches the writer only when sōzune owns its class, so
/// its own conditions are `Accepted=True`/`Programmed=True`; each listener
/// says whether Sōzune serves its port.
async fn patch_gateway_status(client: &Client, scope: &GatewayScope, gateway: &Gateway) {
    let Some(name) = gateway.metadata.name.as_deref() else {
        return;
    };
    let ns = gateway.metadata.namespace.as_deref().unwrap_or("default");
    let ours = build_gateway_conditions(gateway, true);
    let existing = gateway
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_deref());
    let (merged, conditions_changed) = merge_conditions(existing, ours);
    let (listeners, listeners_changed) = merge_listener_statuses(
        gateway.status.as_ref().and_then(|s| s.listeners.as_deref()),
        scope.listener_statuses(gateway),
    );
    if !conditions_changed && !listeners_changed {
        return;
    }
    let patch = serde_json::json!({
        "status": { "conditions": merged, "listeners": listeners }
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
    // Attachment depends on the parentRefs alone, whether or not the route
    // is accepted: it is what a listener's `attachedRoutes` counts.
    scope.record_attachments(
        "HTTPRoute",
        &uid,
        route.metadata.namespace.as_deref().unwrap_or("default"),
        route.spec.hostnames.as_deref().unwrap_or_default(),
        route.spec.parent_refs.as_deref().unwrap_or_default(),
        GatewayScope::listener_serves_http,
    );

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
        // Narrow the route's hostnames by the listener(s) it binds to, over
        // HTTP and over HTTPS: a listener with a `hostname` only serves
        // matching route hostnames. `None` means no bound listener of that
        // kind admits any of the route's hostnames.
        let plain =
            scope.effective_hostnames_for_route(route, GatewayScope::listener_is_plain_http);
        let secure =
            scope.effective_hostnames_for_route(route, GatewayScope::listener_serves_https);
        if plain.is_none() && secure.is_none() {
            (RouteOutcome::NoResolvableBackends, Vec::new())
        } else {
            let eps = route_entrypoints_by_scheme(
                route,
                resolver,
                scope,
                plain,
                secure,
                scope.https_redirect_port(route),
            );
            let outcome = if eps.is_empty() {
                RouteOutcome::NoResolvableBackends
            } else {
                RouteOutcome::Accepted
            };
            (outcome, eps)
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

/// Forget the routes of `kind` a watcher's relist did not return: deleted
/// while the watcher was away, they get no `Delete` event, and would keep
/// routing traffic and counting on their listeners. Returns whether storage
/// changed.
fn drop_routes_not_relisted<T>(
    kind: &'static str,
    relisted: &HashSet<String>,
    index: &RwLock<HashMap<String, T>>,
    entrypoint_ids: fn(&T) -> &[String],
    storage: &RwLock<BTreeMap<String, Entrypoint>>,
    scope: &GatewayScope,
) -> bool {
    // The entrypoint ids of the routes that stay: a route deleted and created
    // again under the same name while the watcher was away has the same ids,
    // and its new version is already installed.
    let (gone, kept): (Vec<(String, T)>, HashSet<String>) = match index.write() {
        Ok(mut index) => {
            let uids: Vec<String> = index
                .keys()
                .filter(|uid| !relisted.contains(*uid))
                .cloned()
                .collect();
            let gone = uids
                .into_iter()
                .filter_map(|uid| index.remove(&uid).map(|tracked| (uid, tracked)))
                .collect();
            let kept = index
                .values()
                .flat_map(|tracked| entrypoint_ids(tracked).iter().cloned())
                .collect();
            (gone, kept)
        }
        Err(e) => {
            error!("Gateway API: index lock poisoned: {}", e);
            return false;
        }
    };
    scope.retain_attachments(kind, relisted);
    if gone.is_empty() {
        return false;
    }
    info!(
        "Gateway API: {} {} route(s) deleted while the watcher was away, removing them",
        gone.len(),
        kind
    );
    let mut storage = match storage.write() {
        Ok(g) => g,
        Err(e) => {
            error!("Gateway API: storage lock poisoned: {}", e);
            return false;
        }
    };
    let mut changed = false;
    for (_, tracked) in gone {
        for id in entrypoint_ids(&tracked) {
            if !kept.contains(id) {
                changed |= storage.remove(id).is_some();
            }
        }
    }
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

/// One backendRef, resolved: its weight, its Service's ready pods and the
/// port to reach them on.
struct ResolvedRef {
    weight: Option<i32>,
    pods: Vec<String>,
    port: u16,
}

/// The largest weight Sōzu takes for a backend.
const MAX_POD_WEIGHT: u128 = i32::MAX as u128;

/// The backends of a rule's backendRefs: each Service's pods, sharing its
/// weight.
///
/// Gateway API weighs a backendRef, not each of its pods: a Service of 3 pods
/// weighted 90 counts for 90, not 270. A pod of a Service of weight `w` and
/// `n` pods gets `w × L / n`, `L` being the least common multiple of the pod
/// counts, so every Service's share is exact; the weights are then divided by
/// their greatest common divisor. When that multiple is too large, each pod's
/// `w / n` is scaled to Sōzu's maximum instead, exact to within one unit per
/// pod. Only when a weight is still past what Sōzu takes are they scaled
/// down, a pod keeping at least 1: a Service's share cannot exceed `i32::MAX`
/// times another's pod count, whatever its weight asks.
///
/// An unset weight is 1; a weight of 0 gets no traffic, so its pods are left
/// out. A rule whose backendRefs all weigh 0 forwards nothing: `Some` with no
/// backend. `None` when the rule has no backendRef, or no ready pod behind a
/// backendRef that has a weight.
fn weigh_backend_refs(refs: Vec<ResolvedRef>) -> Option<Vec<Backend>> {
    if refs.is_empty() {
        return None;
    }
    let weighted: Vec<(u128, ResolvedRef)> = refs
        .into_iter()
        .filter_map(|r| {
            let weight = u128::try_from(r.weight.unwrap_or(1)).unwrap_or(0);
            (weight > 0).then_some((weight, r))
        })
        .collect();
    if weighted.is_empty() {
        return Some(Vec::new());
    }
    let weighted: Vec<(u128, ResolvedRef)> = weighted
        .into_iter()
        .filter(|(_, r)| !r.pods.is_empty())
        .collect();
    if weighted.is_empty() {
        return None;
    }

    let mut per_pod = match least_common_multiple(&weighted) {
        Some(multiple) => {
            let mut per_pod: Vec<u128> = weighted
                .iter()
                .map(|(weight, r)| weight * multiple / r.pods.len() as u128)
                .collect();
            let divisor = per_pod.iter().copied().fold(0, gcd);
            per_pod.iter_mut().for_each(|w| *w /= divisor);
            per_pod
        }
        // Too many distinct pod counts for an exact multiple: each pod's
        // `weight / pods` is scaled so the largest lands on Sōzu's maximum,
        // which keeps every share to within one unit per pod.
        None => {
            let (top_weight, top_pods) = weighted
                .iter()
                .map(|(weight, r)| (*weight, r.pods.len() as u128))
                .max_by(|(wa, na), (wb, nb)| (wa * nb).cmp(&(wb * na)))
                .unwrap_or((1, 1));
            weighted
                .iter()
                .map(|(weight, r)| {
                    weight * MAX_POD_WEIGHT * top_pods / (r.pods.len() as u128 * top_weight)
                })
                .collect()
        }
    };
    let largest = per_pod.iter().copied().max().unwrap_or(1);
    if largest > MAX_POD_WEIGHT {
        per_pod
            .iter_mut()
            .for_each(|w| *w = *w * MAX_POD_WEIGHT / largest);
    }
    per_pod.iter_mut().for_each(|w| *w = (*w).max(1));

    Some(
        weighted
            .into_iter()
            .zip(per_pod)
            .flat_map(|((_, r), weight)| {
                let port = r.port;
                r.pods.into_iter().map(move |address| Backend {
                    address,
                    port,
                    weight: weight as u32,
                })
            })
            .collect(),
    )
}

/// The least common multiple of the rule's pod counts, when it stays within
/// 2^64: past that, the weights it would give no longer fit together.
fn least_common_multiple(weighted: &[(u128, ResolvedRef)]) -> Option<u128> {
    weighted
        .iter()
        .try_fold(1u128, |acc, (_, r)| {
            let pods = r.pods.len() as u128;
            (acc / gcd(acc, pods)).checked_mul(pods)
        })
        .filter(|multiple| *multiple <= u128::from(u64::MAX))
}

fn gcd(a: u128, b: u128) -> u128 {
    if b == 0 { a } else { gcd(b, a % b) }
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

/// The entrypoints of an HTTPRoute, given the hostnames its `HTTP` listeners
/// (`plain`) and its `HTTPS` ones (`secure`) admit. A hostname admitted by
/// both is served over HTTP and HTTPS; one only an `HTTPS` listener admits
/// is served over HTTPS, its plain HTTP requests redirected there; one only
/// an `HTTP` listener admits is served over HTTP. Each set gets its own
/// entrypoints, told apart by a suffix on their ids. `https_port` is where a
/// redirect to HTTPS points, `None` for the default port.
pub fn route_entrypoints_by_scheme(
    route: &HTTPRoute,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
    plain: Option<Vec<String>>,
    secure: Option<Vec<String>>,
    https_port: Option<u16>,
) -> Vec<Entrypoint> {
    // An empty set is every host: what the other scheme names, it admits.
    let plain_all = plain.as_ref().is_some_and(Vec::is_empty);
    let secure_all = secure.as_ref().is_some_and(Vec::is_empty);
    let only_secure = plain.is_none();
    let plain = plain.unwrap_or_default();
    let secure = secure.unwrap_or_default();
    // Served over both: a name one scheme admits that the other covers,
    // itself or through a wildcard.
    let both: Vec<String> = if plain_all {
        secure.clone()
    } else if secure_all {
        plain.clone()
    } else {
        let mut both: Vec<String> = Vec::new();
        for (names, others) in [(&secure, &plain), (&plain, &secure)] {
            for name in names {
                if others.iter().any(|other| hostname_covers(other, name)) && !both.contains(name) {
                    both.push(name.clone());
                }
            }
        }
        both
    };
    let plain_only: Vec<String> = plain
        .iter()
        .filter(|h| !both.contains(h))
        .cloned()
        .collect();
    let secure_only: Vec<String> = secure
        .iter()
        .filter(|h| !both.contains(h))
        .cloned()
        .collect();

    // (hostnames, served over HTTPS, plain HTTP redirected, id suffix)
    let mut sets: Vec<(Vec<String>, bool, bool, &str)> = [
        (plain_only, false, false, ""),
        (both, true, false, "-tls"),
        (secure_only, true, true, "-https"),
    ]
    .into_iter()
    .filter(|(hostnames, ..)| !hostnames.is_empty())
    .collect();
    // A scheme admitting every host keeps the entrypoints it had before
    // HTTPS listeners were served, with no hostname. Sōzu routes on a host,
    // so they serve none, but a route is not dropped by a listener of the
    // other scheme being added.
    if plain_all {
        sets.push((Vec::new(), false, false, ""));
    }
    if secure_all && !plain_all {
        sets.push((Vec::new(), true, true, "-https"));
    }
    if sets.is_empty() {
        sets.push(if only_secure {
            (Vec::new(), true, true, "-https")
        } else {
            (Vec::new(), false, false, "")
        });
    }

    sets.into_iter()
        .flat_map(|(hostnames, tls, redirect, suffix)| {
            route_to_entrypoints_with_hostnames(route, resolver, grants, &hostnames)
                .into_iter()
                .map(move |mut ep| {
                    ep.id.push_str(suffix);
                    ep.name.push_str(suffix);
                    ep.config.tls = tls;
                    ep.config.https_redirect = redirect;
                    if redirect {
                        ep.config.https_redirect_port = https_port;
                    }
                    ep
                })
        })
        .collect()
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
const REASON_NOT_ALLOWED_BY_LISTENERS: &str = "NotAllowedByListeners";
const REASON_NO_MATCHING_PARENT: &str = "NoMatchingParent";

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
    /// (or the route declares no parentRefs at all). Gateway API says
    /// implementations only populate `parents[]` for parents they own, so
    /// the only entries written are refusals by a Gateway of ours.
    NotMine,
}

/// Build the slice of `parents[]` entries sōzune owns for a given
/// route+outcome. Other controllers' entries must be preserved by the
/// caller (see [`merge_route_status`]).
///
/// One entry per parentRef that resolves to a Gateway sōzune accepts, and
/// one `Accepted=False` entry per parentRef such a Gateway refuses (see
/// [`GatewayScope::parent_refusal`]). `Accepted=True` iff [`RouteOutcome::Accepted`]. `ResolvedRefs=True`
/// only when the outcome is `Accepted` (filters and unresolved
/// backends both flip it to False with distinct reasons).
fn build_route_status(
    route: &HTTPRoute,
    scope: &GatewayScope,
    outcome: RouteOutcome,
) -> Vec<HTTPRouteStatusParents> {
    let now = Time(k8s_openapi::chrono::Utc::now());
    let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let generation = route.metadata.generation;
    let condition = |type_: &str, status: &str, reason: &str, message: String| Condition {
        type_: type_.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message,
        last_transition_time: now.clone(),
        observed_generation: generation,
    };

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
        // No parentRef is accepted, so these are never used.
        RouteOutcome::NotMine => ("False", "", String::new()),
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
        RouteOutcome::NotMine => ("False", "", String::new()),
    };

    route
        .spec
        .parent_refs
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|p| {
            let conditions = if scope.accepts_parent_ref(route_ns, p) {
                vec![
                    condition(
                        CONDITION_TYPE_ACCEPTED,
                        accepted_status,
                        accepted_reason,
                        accepted_msg.clone(),
                    ),
                    condition(
                        CONDITION_TYPE_RESOLVED_REFS,
                        refs_status,
                        refs_reason,
                        refs_msg.clone(),
                    ),
                ]
            } else {
                // Reported rather than skipped: silence would read as a
                // Gateway that ignores the route. A parent that is not ours
                // gets no entry.
                let reason = scope.parent_refusal(
                    route_ns,
                    p,
                    "HTTPRoute",
                    GatewayScope::listener_serves_http,
                )?;
                let message = if reason == REASON_NO_MATCHING_PARENT {
                    "No listener of this Gateway matches the parentRef's sectionName and port"
                        .to_string()
                } else {
                    format!(
                        "No HTTP listener selected by this parentRef allows HTTPRoutes from namespace {}",
                        route_ns
                    )
                };
                vec![condition(CONDITION_TYPE_ACCEPTED, "False", reason, message)]
            };
            Some(HTTPRouteStatusParents {
                controller_name: SOZUNE_CONTROLLER_NAME.to_string(),
                parent_ref: HTTPRouteStatusParentsParentRef {
                    group: p.group.clone(),
                    kind: p.kind.clone(),
                    name: p.name.clone(),
                    namespace: p.namespace.clone(),
                    port: p.port,
                    section_name: p.section_name.clone(),
                },
                conditions: Some(conditions),
            })
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
    let resolved: Vec<ResolvedRef> = backend_refs
        .iter()
        .filter_map(|b| {
            let port = u16::try_from(b.port?).ok()?;
            // Service-typed backends only for v1. group/kind defaulting to
            // empty/Service per Gateway API spec is what we accept; anything
            // else (e.g. an external resource) is out of scope.
            let kind_ok = b.kind.as_deref().map(|k| k == "Service").unwrap_or(true);
            let group_ok = b.group.as_deref().map(|g| g.is_empty()).unwrap_or(true);
            if !kind_ok || !group_ok {
                return None;
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
                return None;
            }
            Some(ResolvedRef {
                weight: b.weight,
                pods: resolver.pod_ips(target_ns, &b.name),
                port,
            })
        })
        .collect();
    let Some(backends) = weigh_backend_refs(resolved) else {
        return Vec::new();
    };

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
                candidates: Vec::new(),
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
    // Attachment depends on the parentRefs alone, whether or not the route
    // is accepted: it is what a listener's `attachedRoutes` counts.
    scope.record_attachments(
        "TLSRoute",
        &uid,
        route.metadata.namespace.as_deref().unwrap_or("default"),
        route.spec.hostnames.as_deref().unwrap_or_default(),
        route.spec.parent_refs.as_deref().unwrap_or_default(),
        GatewayScope::listener_serves_tls_passthrough,
    );

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
            .flat_map(|(port, hostnames)| match listener_ports.get(port) {
                Some(listener_name) => {
                    tls_route_to_entrypoints(route, resolver, scope, &hostnames, &listener_name, port)
                }
                None => {
                    let ns = route.metadata.namespace.as_deref().unwrap_or("default");
                    let name = route.metadata.name.as_deref().unwrap_or("<no-name>");
                    warn!(
                        "Gateway API: TLSRoute {}/{} binds to a Gateway listener on port {}, which is neither a `proxy.tcp` listener nor in `proxy.gateway_ports.tcp` in config.yaml",
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
    // The routes the current relist returned; the others were deleted while
    // the watcher was away.
    let mut relisted: Option<HashSet<String>> = None;

    loop {
        let changed = tokio::select! {
            event = stream.next() => match event {
                Some(Ok(Event::Apply(route))) | Some(Ok(Event::InitApply(route))) => {
                    if let (Some(uids), Some(uid)) = (relisted.as_mut(), route.metadata.uid.as_deref()) {
                        uids.insert(uid.to_string());
                    }
                    log_tls_route("apply", &route);
                    apply_tls_route(&route, &storage, &index, resolver.as_ref(), &scope, &listener_ports)
                }
                Some(Ok(Event::Delete(route))) => {
                    log_tls_route("delete", &route);
                    if let Some(uid) = route.metadata.uid.as_deref() {
                        scope.forget_attachments("TLSRoute", uid);
                    }
                    delete_tls_route(&route, &storage, &index)
                }
                Some(Ok(Event::Init)) => {
                    debug!("Gateway API: TLSRoute init");
                    relisted = Some(HashSet::new());
                    false
                }
                Some(Ok(Event::InitDone)) => {
                    debug!("Gateway API: TLSRoute init done");
                    match relisted.take() {
                        Some(uids) => drop_routes_not_relisted(
                            "TLSRoute",
                            &uids,
                            &index,
                            |t: &TrackedTlsRoute| t.entrypoint_ids.as_slice(),
                            &storage,
                            &scope,
                        ),
                        None => false,
                    }
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
            let backends = tcp_rule_backends(rule, namespace, route_name, resolver, grants)?;
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
                candidates: Vec::new(),
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
) -> Option<Vec<Backend>> {
    let backend_refs = rule.backend_refs.as_ref()?;
    let resolved: Vec<ResolvedRef> = backend_refs
        .iter()
        .filter_map(|b| {
            let port = u16::try_from(b.port?).ok()?;
            let kind_ok = b.kind.as_deref().map(|k| k == "Service").unwrap_or(true);
            let group_ok = b.group.as_deref().map(|g| g.is_empty()).unwrap_or(true);
            if !kind_ok || !group_ok {
                return None;
            }
            let target_ns = b.namespace.as_deref().unwrap_or(namespace);
            if !grants.allows(namespace, target_ns) {
                warn!(
                    "Gateway API: TCPRoute {}/{} references Service {}/{} across namespaces with no ReferenceGrant — dropping the backend",
                    namespace, route_name, target_ns, b.name
                );
                return None;
            }
            Some(ResolvedRef {
                weight: b.weight,
                pods: resolver.pod_ips(target_ns, &b.name),
                port,
            })
        })
        .collect();
    weigh_backend_refs(resolved)
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
    // Attachment depends on the parentRefs alone, whether or not the route
    // is accepted: it is what a listener's `attachedRoutes` counts.
    scope.record_attachments(
        "TCPRoute",
        &uid,
        route.metadata.namespace.as_deref().unwrap_or("default"),
        &[],
        route.spec.parent_refs.as_deref().unwrap_or_default(),
        GatewayScope::listener_serves_tcp,
    );

    let new_entrypoints = if !scope.accepts_tcp_route(route) {
        Vec::new()
    } else {
        scope
            .effective_tcp_ports(route)
            .into_iter()
            .flat_map(|port| match listener_ports.get(port) {
                Some(listener_name) => {
                    tcp_route_to_entrypoints(route, resolver, scope, &listener_name, port)
                }
                None => {
                    let ns = route.metadata.namespace.as_deref().unwrap_or("default");
                    let name = route.metadata.name.as_deref().unwrap_or("<no-name>");
                    warn!(
                        "Gateway API: TCPRoute {}/{} binds to a Gateway listener on port {}, which is neither a `proxy.tcp` listener nor in `proxy.gateway_ports.tcp` in config.yaml",
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
    // The routes the current relist returned; the others were deleted while
    // the watcher was away.
    let mut relisted: Option<HashSet<String>> = None;

    loop {
        let changed = tokio::select! {
            event = stream.next() => match event {
                Some(Ok(Event::Apply(route))) | Some(Ok(Event::InitApply(route))) => {
                    if let (Some(uids), Some(uid)) = (relisted.as_mut(), route.metadata.uid.as_deref()) {
                        uids.insert(uid.to_string());
                    }
                    log_tcp_route("apply", &route);
                    apply_tcp_route(&route, &storage, &index, resolver.as_ref(), &scope, &listener_ports)
                }
                Some(Ok(Event::Delete(route))) => {
                    log_tcp_route("delete", &route);
                    if let Some(uid) = route.metadata.uid.as_deref() {
                        scope.forget_attachments("TCPRoute", uid);
                    }
                    delete_tcp_route(&route, &storage, &index)
                }
                Some(Ok(Event::Init)) => {
                    debug!("Gateway API: TCPRoute init");
                    relisted = Some(HashSet::new());
                    false
                }
                Some(Ok(Event::InitDone)) => {
                    debug!("Gateway API: TCPRoute init done");
                    match relisted.take() {
                        Some(uids) => drop_routes_not_relisted(
                            "TCPRoute",
                            &uids,
                            &index,
                            |t: &TrackedTcpRoute| t.entrypoint_ids.as_slice(),
                            &storage,
                            &scope,
                        ),
                        None => false,
                    }
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

// ---------- UDPRoute ----------
//
// The datagram twin of TCPRoute: forward a whole `proxy.udp` listener port to
// the backends, one catch-all `Protocol::Udp` entrypoint per (route, port).

/// Maps a Gateway listener port onto the `proxy.udp` listener serving it, as
/// [`TcpListenerPorts`] does for TCP.
pub type UdpListenerPorts = Arc<ListenerPorts>;

pub fn udp_listener_ports(
    udp: &[crate::config::UdpListenerConfig],
    gateway_ports: &crate::config::GatewayPortsConfig,
) -> UdpListenerPorts {
    Arc::new(ListenerPorts {
        declared: udp
            .iter()
            .map(|l| (i32::from(l.listen), l.name.clone()))
            .collect(),
        open: gateway_ports.udp.clone(),
        open_name: crate::config::gateway_udp_listener,
    })
}

struct TrackedUdpRoute {
    route: UDPRoute,
    entrypoint_ids: Vec<String>,
}

type UdpRouteIndex = Arc<RwLock<HashMap<String, TrackedUdpRoute>>>;

/// Convert a UDPRoute into `Protocol::Udp` entrypoints, one catch-all per rule
/// on the resolved listener.
pub fn udp_route_to_entrypoints(
    route: &UDPRoute,
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
            let backends = udp_rule_backends(rule, namespace, route_name, resolver, grants)?;
            Some(Entrypoint {
                id: format!("{SOURCE_TAG}-udp/{namespace}/{route_name}/{port}/{rule_index}"),
                name: format!("{route_name}-{port}-{rule_index}"),
                backends,
                protocol: Protocol::Udp,
                config: EntrypointConfig {
                    entrypoint: Some(listener_name.to_string()),
                    ..tls_entrypoint_defaults()
                },
                source: Some(format!("{SOURCE_TAG}-udp/{namespace}/{route_name}")),
                candidates: Vec::new(),
            })
        })
        .collect()
}

/// Resolve a UDPRoute rule's `backendRefs` to pod IPs. Same handling as the TCP
/// path; duplicated because `UDPRouteRules` is a distinct generated type.
fn udp_rule_backends(
    rule: &UDPRouteRules,
    namespace: &str,
    route_name: &str,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
) -> Option<Vec<Backend>> {
    let backend_refs = rule.backend_refs.as_ref()?;
    let resolved: Vec<ResolvedRef> = backend_refs
        .iter()
        .filter_map(|b| {
            let port = u16::try_from(b.port?).ok()?;
            let kind_ok = b.kind.as_deref().map(|k| k == "Service").unwrap_or(true);
            let group_ok = b.group.as_deref().map(|g| g.is_empty()).unwrap_or(true);
            if !kind_ok || !group_ok {
                return None;
            }
            let target_ns = b.namespace.as_deref().unwrap_or(namespace);
            if !grants.allows(namespace, target_ns) {
                warn!(
                    "Gateway API: UDPRoute {}/{} references Service {}/{} across namespaces with no ReferenceGrant — dropping the backend",
                    namespace, route_name, target_ns, b.name
                );
                return None;
            }
            Some(ResolvedRef {
                weight: b.weight,
                pods: resolver.pod_ips(target_ns, &b.name),
                port,
            })
        })
        .collect();
    weigh_backend_refs(resolved)
}

fn apply_udp_route(
    route: &UDPRoute,
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &UdpRouteIndex,
    resolver: &dyn ServiceResolver,
    scope: &GatewayScope,
    listener_ports: &UdpListenerPorts,
) -> bool {
    let uid = match route.metadata.uid.as_deref() {
        Some(u) => u.to_string(),
        None => {
            warn!("Gateway API: UDPRoute without uid, skipping");
            return false;
        }
    };
    // Attachment depends on the parentRefs alone, whether or not the route
    // is accepted: it is what a listener's `attachedRoutes` counts.
    scope.record_attachments(
        "UDPRoute",
        &uid,
        route.metadata.namespace.as_deref().unwrap_or("default"),
        &[],
        route.spec.parent_refs.as_deref().unwrap_or_default(),
        GatewayScope::listener_serves_udp,
    );

    let new_entrypoints = if !scope.accepts_udp_route(route) {
        Vec::new()
    } else {
        scope
            .effective_udp_ports(route)
            .into_iter()
            .flat_map(|port| match listener_ports.get(port) {
                Some(listener_name) => {
                    udp_route_to_entrypoints(route, resolver, scope, &listener_name, port)
                }
                None => {
                    let ns = route.metadata.namespace.as_deref().unwrap_or("default");
                    let name = route.metadata.name.as_deref().unwrap_or("<no-name>");
                    warn!(
                        "Gateway API: UDPRoute {}/{} binds to a Gateway listener on port {}, which is neither a `proxy.udp` listener nor in `proxy.gateway_ports.udp` in config.yaml",
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
        TrackedUdpRoute {
            route: route.clone(),
            entrypoint_ids: new_ids,
        },
    );

    changed
}

fn delete_udp_route(
    route: &UDPRoute,
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &UdpRouteIndex,
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

fn re_resolve_all_udp(
    storage: &Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    index: &UdpRouteIndex,
    resolver: &dyn ServiceResolver,
    scope: &GatewayScope,
    listener_ports: &UdpListenerPorts,
) -> bool {
    let tracked: Vec<UDPRoute> = match index.read() {
        Ok(g) => g.values().map(|t| t.route.clone()).collect(),
        Err(e) => {
            error!("Gateway API: index lock poisoned: {}", e);
            return false;
        }
    };

    let mut changed = false;
    for route in &tracked {
        if apply_udp_route(route, storage, index, resolver, scope, listener_ports) {
            changed = true;
        }
    }
    changed
}

/// Watch UDPRoutes and keep their entrypoints in sync. `v1alpha2`/experimental
/// like TCPRoute, so the CRD is probed and the watcher exits quietly if absent.
pub async fn run_udproute_watcher(
    client: Client,
    storage: Arc<RwLock<BTreeMap<String, Entrypoint>>>,
    reload_tx: mpsc::Sender<()>,
    resolver: Arc<dyn ServiceResolver>,
    scope: GatewayScope,
    listener_ports: UdpListenerPorts,
) -> anyhow::Result<()> {
    let api: Api<UDPRoute> = Api::all(client);
    if api.list(&Default::default()).await.is_err() {
        info!(
            "Gateway API: UDPRoute CRD not installed, skipping watcher (it ships in the experimental bundle)"
        );
        return Ok(());
    }

    let mut stream = watcher::watcher(api, watcher::Config::default()).boxed();
    let index: UdpRouteIndex = Arc::new(RwLock::new(HashMap::new()));
    let mut resolve_ticker = tokio::time::interval(std::time::Duration::from_secs(2));
    resolve_ticker.tick().await;

    info!("Gateway API: UDPRoute watcher started");
    // The routes the current relist returned; the others were deleted while
    // the watcher was away.
    let mut relisted: Option<HashSet<String>> = None;

    loop {
        let changed = tokio::select! {
            event = stream.next() => match event {
                Some(Ok(Event::Apply(route))) | Some(Ok(Event::InitApply(route))) => {
                    if let (Some(uids), Some(uid)) = (relisted.as_mut(), route.metadata.uid.as_deref()) {
                        uids.insert(uid.to_string());
                    }
                    log_udp_route("apply", &route);
                    apply_udp_route(&route, &storage, &index, resolver.as_ref(), &scope, &listener_ports)
                }
                Some(Ok(Event::Delete(route))) => {
                    log_udp_route("delete", &route);
                    if let Some(uid) = route.metadata.uid.as_deref() {
                        scope.forget_attachments("UDPRoute", uid);
                    }
                    delete_udp_route(&route, &storage, &index)
                }
                Some(Ok(Event::Init)) => {
                    debug!("Gateway API: UDPRoute init");
                    relisted = Some(HashSet::new());
                    false
                }
                Some(Ok(Event::InitDone)) => {
                    debug!("Gateway API: UDPRoute init done");
                    match relisted.take() {
                        Some(uids) => drop_routes_not_relisted(
                            "UDPRoute",
                            &uids,
                            &index,
                            |t: &TrackedUdpRoute| t.entrypoint_ids.as_slice(),
                            &storage,
                            &scope,
                        ),
                        None => false,
                    }
                }
                Some(Err(e)) => {
                    error!("Gateway API: UDPRoute watcher error: {}", e);
                    false
                }
                None => break,
            },
            _ = resolve_ticker.tick() => {
                re_resolve_all_udp(&storage, &index, resolver.as_ref(), &scope, &listener_ports)
            }
            _ = scope.changed() => {
                debug!("Gateway API: scope changed, re-resolving UDP routes");
                re_resolve_all_udp(&storage, &index, resolver.as_ref(), &scope, &listener_ports)
            }
        };
        if changed && let Err(e) = reload_tx.send(()).await {
            error!("Gateway API: failed to send reload signal: {}", e);
        }
    }

    warn!("Gateway API: UDPRoute watcher stream ended unexpectedly");
    Ok(())
}

fn log_udp_route(action: &str, route: &UDPRoute) {
    let ns = route
        .metadata
        .namespace
        .as_deref()
        .unwrap_or("<no-namespace>");
    let name = route.metadata.name.as_deref().unwrap_or("<no-name>");
    debug!("Gateway API: UDPRoute {} {}/{}", action, ns, name);
}

/// Maps a Gateway listener port onto the listener serving it: the `proxy.tcp`
/// entry declared on that port, or else the one Sōzune opens there when
/// `proxy.gateway_ports.tcp` lists the port. A Gateway declaring `port: 8443`
/// is served only in one of these two cases. Built once at startup and read
/// on every route apply.
pub type TcpListenerPorts = Arc<ListenerPorts>;

/// The listener serving each port a Gateway listener may declare.
pub struct ListenerPorts {
    declared: HashMap<i32, String>,
    open: Vec<crate::config::PortRange>,
    open_name: fn(u16) -> String,
}

impl ListenerPorts {
    /// The listener serving `port`. A declared one wins over opening the port.
    pub fn get(&self, port: i32) -> Option<String> {
        if let Some(name) = self.declared.get(&port) {
            return Some(name.clone());
        }
        let port = u16::try_from(port).ok()?;
        self.open
            .iter()
            .any(|r| r.contains(port))
            .then(|| (self.open_name)(port))
    }
}

/// A table of declared listeners only, opening no port.
#[cfg(test)]
impl FromIterator<(i32, String)> for ListenerPorts {
    fn from_iter<I: IntoIterator<Item = (i32, String)>>(iter: I) -> Self {
        Self {
            declared: iter.into_iter().collect(),
            open: Vec::new(),
            open_name: crate::config::gateway_tcp_listener,
        }
    }
}

/// Build the port → listener-name table from the proxy config.
pub fn tcp_listener_ports(
    tcp: &[crate::config::TcpListenerConfig],
    gateway_ports: &crate::config::GatewayPortsConfig,
) -> TcpListenerPorts {
    Arc::new(ListenerPorts {
        declared: tcp
            .iter()
            .map(|l| (i32::from(l.listen), l.name.clone()))
            .collect(),
        open: gateway_ports.tcp.clone(),
        open_name: crate::config::gateway_tcp_listener,
    })
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
            let Some(backends) = tls_rule_backends(rule, namespace, route_name, resolver, grants)
            else {
                return Vec::new();
            };

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
                        candidates: Vec::new(),
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
) -> Option<Vec<Backend>> {
    let backend_refs = rule.backend_refs.as_ref()?;
    let resolved: Vec<ResolvedRef> = backend_refs
        .iter()
        .filter_map(|b| {
            let port = u16::try_from(b.port?).ok()?;
            let kind_ok = b.kind.as_deref().map(|k| k == "Service").unwrap_or(true);
            let group_ok = b.group.as_deref().map(|g| g.is_empty()).unwrap_or(true);
            if !kind_ok || !group_ok {
                return None;
            }
            let target_ns = b.namespace.as_deref().unwrap_or(namespace);
            if !grants.allows(namespace, target_ns) {
                warn!(
                    "Gateway API: TLSRoute {}/{} references Service {}/{} across namespaces with no ReferenceGrant — dropping the backend",
                    namespace, route_name, target_ns, b.name
                );
                return None;
            }
            Some(ResolvedRef {
                weight: b.weight,
                pods: resolver.pod_ips(target_ns, &b.name),
                port,
            })
        })
        .collect();
    weigh_backend_refs(resolved)
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
    use gateway_api::apis::standard::gateways::{
        GatewayListeners, GatewayListenersAllowedRoutes, GatewayListenersAllowedRoutesKinds,
        GatewayListenersAllowedRoutesNamespaces, GatewaySpec,
    };
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
                listeners: vec![gw_listener("http", 80, "HTTP")],
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
        assert!(ports_8443().get(9443).is_none());
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
                idle_timeout: None,
            },
            crate::config::TcpListenerConfig {
                name: "pg".into(),
                listen: 5432,
                ip_allow_list: Vec::new(),
                rate_limit: None,
                sni_preread_timeout: None,
                sni_preread_max_bytes: None,
                idle_timeout: None,
            },
        ];
        let ports = tcp_listener_ports(&listeners, &Default::default());
        assert_eq!(ports.get(8443).as_deref(), Some("tlsgw"));
        assert_eq!(ports.get(5432).as_deref(), Some("pg"));
        assert!(ports.get(443).is_none());
    }

    #[test]
    fn a_gateway_port_resolves_to_the_listener_opened_there() {
        let listeners = vec![crate::config::TcpListenerConfig {
            name: "pg".into(),
            listen: 5432,
            ip_allow_list: Vec::new(),
            rate_limit: None,
            sni_preread_timeout: None,
            sni_preread_max_bytes: None,
            idle_timeout: None,
        }];
        let gateway_ports = crate::config::GatewayPortsConfig {
            tcp: vec!["5000-5500".parse().unwrap()],
            udp: Vec::new(),
        };
        let ports = tcp_listener_ports(&listeners, &gateway_ports);
        // A declared listener wins over opening its port.
        assert_eq!(ports.get(5432).as_deref(), Some("pg"));
        assert_eq!(
            ports.get(5433),
            Some(crate::config::gateway_tcp_listener(5433))
        );
        assert!(ports.get(5501).is_none());
        assert!(ports.get(-1).is_none());
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
        let scope = default_scope(); // gw with a single HTTP listener
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

    // ---------- UDPRoute ----------

    fn udp_scope(port: i32) -> GatewayScope {
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
                    name: "udp".into(),
                    port,
                    protocol: "UDP".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            status: Default::default(),
        });
        scope
    }

    fn udp_route(backend_port: i32) -> UDPRoute {
        UDPRoute {
            metadata: ObjectMeta {
                name: Some("dgram".into()),
                namespace: Some("default".into()),
                uid: Some("uid-udp-1".into()),
                ..Default::default()
            },
            spec: gateway_api::apis::experimental::udproutes::UDPRouteSpec {
                parent_refs: Some(vec![UDPRouteParentRefs {
                    name: "gw".into(),
                    ..Default::default()
                }]),
                rules: vec![UDPRouteRules {
                    backend_refs: Some(vec![
                        gateway_api::apis::experimental::udproutes::UDPRouteRulesBackendRefs {
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

    fn udp_ports() -> UdpListenerPorts {
        Arc::new([(53, "dns".to_string())].into_iter().collect())
    }

    #[test]
    fn udp_route_produces_one_catch_all_entrypoint_per_rule() {
        let scope = udp_scope(53);
        let route = udp_route(53);
        assert!(scope.effective_udp_ports(&route).contains(&53));

        let eps = udp_route_to_entrypoints(&route, &r1(), &scope, "dns", 53);
        assert_eq!(eps.len(), 1);
        let ep = &eps[0];
        assert!(matches!(ep.protocol, Protocol::Udp));
        assert_eq!(ep.config.entrypoint.as_deref(), Some("dns"));
        assert_eq!(ep.config.sni, None);
        assert!(ep.config.hostnames.is_empty());
        assert_eq!(ep.backends[0].port, 53);
    }

    #[test]
    fn udp_route_needs_a_udp_listener() {
        // A TCP listener is not a UDP listener.
        let scope = tcp_scope(53);
        assert!(!scope.accepts_udp_route(&udp_route(53)));
    }

    #[test]
    fn udp_route_with_unresolvable_backend_produces_nothing() {
        let scope = udp_scope(53);
        let eps = udp_route_to_entrypoints(&udp_route(53), &r0(), &scope, "dns", 53);
        assert!(eps.is_empty());
    }

    #[test]
    fn udp_apply_and_delete_round_trip_through_storage() {
        let scope = udp_scope(53);
        let storage: Arc<RwLock<BTreeMap<String, Entrypoint>>> =
            Arc::new(RwLock::new(BTreeMap::new()));
        let index: UdpRouteIndex = Arc::new(RwLock::new(HashMap::new()));
        let route = udp_route(53);

        assert!(apply_udp_route(
            &route,
            &storage,
            &index,
            &r1(),
            &scope,
            &udp_ports()
        ));
        assert_eq!(storage.read().unwrap().len(), 1);

        assert!(delete_udp_route(&route, &storage, &index));
        assert!(storage.read().unwrap().is_empty());
    }

    #[test]
    fn udp_entrypoint_ids_cannot_collide_with_tcp() {
        // Distinct `-udp/` vs `-tcp/` prefixes keep the kinds apart.
        let scope = udp_scope(53);
        let eps = udp_route_to_entrypoints(&udp_route(53), &r1(), &scope, "dns", 53);
        assert!(eps[0].id.starts_with("k8s-gateway-udp/"));
    }

    #[test]
    fn udp_listener_ports_maps_port_to_name() {
        let listeners = vec![crate::config::UdpListenerConfig {
            name: "dns".into(),
            listen: 53,
        }];
        let gateway_ports = crate::config::GatewayPortsConfig {
            tcp: vec!["5353".parse().unwrap()],
            udp: vec!["5353".parse().unwrap()],
        };
        let ports = udp_listener_ports(&listeners, &gateway_ports);
        assert_eq!(ports.get(53).as_deref(), Some("dns"));
        assert_eq!(
            ports.get(5353),
            Some(crate::config::gateway_udp_listener(5353))
        );
        assert!(ports.get(443).is_none());
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
        // A lone backendRef takes every request, whatever its weight.
        assert_eq!(eps[0].backends.len(), 1);
        assert!(eps[0].backends[0].weight >= 1);
    }

    fn resolved(weight: Option<i32>, pods: usize) -> ResolvedRef {
        ResolvedRef {
            weight,
            pods: (0..pods)
                .map(|i| format!("10.{}.{}.{}", pods % 256, i / 256, i % 256))
                .collect(),
            port: 80,
        }
    }

    /// Each Service's total weight, in the order the refs were given.
    fn service_shares(refs: Vec<ResolvedRef>) -> Vec<u64> {
        let mut by_service: Vec<(String, u64)> = Vec::new();
        for backend in weigh_backend_refs(refs).unwrap() {
            let service = backend.address.split('.').nth(1).unwrap().to_string();
            match by_service.iter_mut().find(|(s, _)| *s == service) {
                Some((_, total)) => *total += u64::from(backend.weight),
                None => by_service.push((service, u64::from(backend.weight))),
            }
        }
        by_service.into_iter().map(|(_, total)| total).collect()
    }

    /// A backendRef's weight is the Service's share, whatever its number of
    /// pods: 3 pods weighted 90 against 1 pod weighted 10 is a 90/10 split.
    #[test]
    fn a_backend_ref_weight_is_shared_by_its_pods() {
        let shares = service_shares(vec![resolved(Some(90), 3), resolved(Some(10), 1)]);
        assert_eq!(shares[0] * 10, shares[1] * 90);
    }

    /// The ratio holds with thousands of pods, where a fixed scale would
    /// floor each pod at 1 and let the big Service outweigh its weight.
    #[test]
    fn the_ratio_holds_for_large_services() {
        let shares = service_shares(vec![resolved(Some(1), 5000), resolved(Some(1), 1)]);
        assert_eq!(shares[0], shares[1]);
        let shares = service_shares(vec![resolved(Some(1_000_000), 3), resolved(Some(1), 7)]);
        assert_eq!(shares[0], shares[1] * 1_000_000);
    }

    /// Gateway API: an unset weight is 1, and a weight of 0 gets no traffic.
    #[test]
    fn an_unset_weight_is_one_and_zero_gets_no_traffic() {
        let shares = service_shares(vec![resolved(None, 1), resolved(Some(1), 2)]);
        assert_eq!(shares[0], shares[1]);
        let backends =
            weigh_backend_refs(vec![resolved(Some(0), 1), resolved(Some(2), 1)]).unwrap();
        assert_eq!(backends.len(), 1);
        assert!(
            weigh_backend_refs(vec![resolved(Some(-3), 1), resolved(Some(1), 1)])
                .unwrap()
                .len()
                == 1
        );
    }

    /// No ready pod at all is "not found"; pods that all weigh 0 are a rule
    /// that forwards nothing.
    #[test]
    fn an_all_zero_rule_is_not_a_missing_backend() {
        assert!(weigh_backend_refs(vec![resolved(Some(1), 0)]).is_none());
        assert!(weigh_backend_refs(Vec::new()).is_none());
        assert_eq!(
            weigh_backend_refs(vec![resolved(Some(0), 2)]),
            Some(Vec::new())
        );
        // Decided by the weights, whether or not the pods are ready.
        assert_eq!(
            weigh_backend_refs(vec![resolved(Some(0), 0)]),
            Some(Vec::new())
        );
    }

    /// A share past what integer weights can express is kept as close as
    /// they allow: the big Service at Sōzu's maximum, each pod of the other
    /// at 1.
    #[test]
    fn a_share_too_large_for_sozu_is_capped() {
        let backends =
            weigh_backend_refs(vec![resolved(Some(1_000_000), 1), resolved(Some(1), 2500)])
                .unwrap();
        assert_eq!(backends[0].weight, i32::MAX as u32);
        assert!(backends[1..].iter().all(|b| b.weight == 1));
    }

    /// Pod counts too varied for an exact multiple still give equal weights
    /// equal shares.
    #[test]
    fn varied_pod_counts_keep_equal_shares() {
        let counts = [101, 103, 107, 109, 113, 127, 131, 137, 139, 149];
        let shares = service_shares(counts.iter().map(|&n| resolved(Some(1), n)).collect());
        let (low, high) = (*shares.iter().min().unwrap(), *shares.iter().max().unwrap());
        assert!(high - low <= 149, "shares {shares:?}");
        assert!(low > 1_000_000);
    }

    /// Exact shares are reduced to their smallest weights.
    #[test]
    fn exact_shares_use_the_smallest_weights() {
        let backends =
            weigh_backend_refs(vec![resolved(Some(3), 3), resolved(Some(2), 2)]).unwrap();
        assert!(backends.iter().all(|b| b.weight == 1));
    }

    /// Every weight fits what Sōzu takes.
    #[test]
    fn weights_stay_within_what_sozu_takes() {
        let backends =
            weigh_backend_refs(vec![resolved(Some(i32::MAX), 1), resolved(Some(1), 3)]).unwrap();
        assert!(
            backends
                .iter()
                .all(|b| b.weight >= 1 && b.weight <= i32::MAX as u32)
        );
    }

    /// The route keeps the backendRefs with a weight and drops one at 0.
    #[test]
    fn a_zero_weight_backend_ref_is_left_out_of_the_route() {
        let mut on = backend("api", 80);
        on.weight = Some(1);
        let mut off = backend("api", 80);
        off.weight = Some(0);
        let r = route_with(
            vec![rule(None, vec![on, off])],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps[0].backends.len(), 1);
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
    fn build_status_reports_a_parent_whose_listeners_refuse_the_route() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        scope.upsert_gateway(&gateway("infra", "gw", "sozune"));
        let mut r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![
                parent("foreign-gw"),
                HTTPRouteParentRefs {
                    name: "gw".into(),
                    namespace: Some("infra".into()),
                    ..Default::default()
                },
            ],
        );
        r.metadata.namespace = Some("apps".into());

        let parents = build_route_status(&r, &scope, RouteOutcome::NotMine);
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].parent_ref.name, "gw");
        let conditions = parents[0].conditions.as_deref().unwrap_or_default();
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0].type_, CONDITION_TYPE_ACCEPTED);
        assert_eq!(conditions[0].status, "False");
        assert_eq!(conditions[0].reason, REASON_NOT_ALLOWED_BY_LISTENERS);
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
                // The CRD requires a listener; this one admits routes of the
                // Gateway's own namespace, as an unset `allowedRoutes` does.
                listeners: vec![gw_listener("http", 80, "HTTP")],
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
            allowed_namespaces: AllowedNamespaces::Same,
            allowed_kinds: None,
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
            allowed_namespaces: AllowedNamespaces::Same,
            allowed_kinds: None,
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
    fn a_wildcard_route_hostname_narrows_to_the_listener() {
        let listeners = vec![
            li("web", 80, Some("web.example.com")),
            li("api", 80, Some("*.api.example.com")),
        ];
        let got = intersect_hostnames(&["*.example.com".into()], &listeners);
        assert_eq!(
            got,
            Some(vec![
                "web.example.com".to_string(),
                "*.api.example.com".to_string()
            ])
        );
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

    // ---------- Listener status ----------

    fn served() -> ServedPorts {
        ServedPorts {
            http: 80,
            https: 443,
            tcp: HashSet::from([5432]),
            udp: HashSet::from([53]),
            gateway: crate::config::GatewayPortsConfig {
                tcp: vec!["9000-9099".parse().unwrap()],
                udp: vec!["5353".parse().unwrap()],
            },
            unopened: Default::default(),
        }
    }

    fn gw_listener(name: &str, port: i32, protocol: &str) -> GatewayListeners {
        GatewayListeners {
            name: name.into(),
            port,
            protocol: protocol.into(),
            ..Default::default()
        }
    }

    fn condition_of<'a>(
        status: &'a gateway_api::apis::standard::gateways::GatewayStatusListeners,
        type_: &str,
    ) -> &'a Condition {
        status.conditions.iter().find(|c| c.type_ == type_).unwrap()
    }

    /// The status follows routing: an HTTP listener is served on any port,
    /// a TCP or UDP one only on a port a `proxy.tcp`/`proxy.udp` entry
    /// listens on; any other is reported, with what to declare.
    fn https_listener(name: &str, secret_ns: Option<&str>, secret: &str) -> GatewayListeners {
        let mut l = gw_listener(name, 443, "HTTPS");
        l.tls = Some(gateway_api::apis::standard::gateways::GatewayListenersTls {
            certificate_refs: Some(vec![GatewayListenersTlsCertificateRefs {
                name: secret.into(),
                namespace: secret_ns.map(str::to_string),
                ..Default::default()
            }]),
            ..Default::default()
        });
        l
    }

    fn store_secret(scope: &GatewayScope, ns: &str, name: &str, host: &str) -> String {
        let (cert, key) = super::super::gateway_tls::tests::self_signed(&[host]);
        let secret = super::super::gateway_tls::tests::tls_secret(ns, name, &cert, &key);
        let certificate = super::super::gateway_tls::certificate_from_secret(&secret).unwrap();
        let fingerprint = certificate.fingerprint.clone();
        scope.upsert_tls_secret((ns.into(), name.into()), Ok(Arc::new(certificate)));
        fingerprint
    }

    fn resolved_refs(scope: &GatewayScope, gw: &Gateway, listener: &str) -> Condition {
        let statuses = scope.listener_statuses(gw);
        let status = statuses.iter().find(|l| l.name == listener).unwrap();
        condition_of(status, CONDITION_TYPE_RESOLVED_REFS).clone()
    }

    /// An accepted Gateway's HTTPS listeners hand over the certificates their
    /// certificateRefs name, and their status says when one cannot be used.
    #[test]
    fn https_listeners_take_the_certificates_they_reference() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        gw.spec.listeners = vec![
            https_listener("shop", None, "shop-tls"),
            https_listener("other", Some("infra"), "infra-tls"),
            https_listener("ghost", None, "nowhere"),
        ];
        scope.upsert_gateway(&gw);
        let shop = store_secret(&scope, "default", "shop-tls", "shop.example.com");
        store_secret(&scope, "infra", "infra-tls", "infra.example.com");

        let served: Vec<String> = scope
            .referenced_certificates()
            .iter()
            .map(|c| c.fingerprint.clone())
            .collect();
        assert_eq!(served, [shop]);

        assert_eq!(resolved_refs(&scope, &gw, "shop").status, "True");
        assert_eq!(
            resolved_refs(&scope, &gw, "other").reason,
            REASON_REF_NOT_PERMITTED
        );
        let ghost = resolved_refs(&scope, &gw, "ghost");
        assert_eq!(ghost.reason, REASON_INVALID_CERTIFICATE_REF);
        assert!(ghost.message.contains("default/nowhere"));
        let statuses = scope.listener_statuses(&gw);
        let ghost = statuses.iter().find(|l| l.name == "ghost").unwrap();
        assert_eq!(
            condition_of(ghost, CONDITION_TYPE_PROGRAMMED).status,
            "False"
        );

        // A Secret that becomes unusable is no longer served.
        scope.upsert_tls_secret(
            ("default".into(), "shop-tls".into()),
            Err("the certificate has expired".into()),
        );
        assert!(scope.referenced_certificates().is_empty());
        assert!(
            resolved_refs(&scope, &gw, "shop")
                .message
                .contains("the certificate has expired")
        );
    }

    /// A certificate is only used by a listener whose hostname it covers,
    /// and stops being used once it expires.
    #[test]
    fn a_listener_takes_a_certificate_covering_it_until_it_expires() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        let mut api = https_listener("api", None, "wildcard-tls");
        api.hostname = Some("api.example.com".into());
        let mut shop = https_listener("shop", None, "other-tls");
        shop.hostname = Some("shop.example.com".into());
        gw.spec.listeners = vec![api, shop];
        scope.upsert_gateway(&gw);
        store_secret(&scope, "default", "wildcard-tls", "*.example.com");
        store_secret(&scope, "default", "other-tls", "other.example.com");

        assert_eq!(resolved_refs(&scope, &gw, "api").status, "True");
        let shop = resolved_refs(&scope, &gw, "shop");
        assert_eq!(shop.reason, REASON_INVALID_CERTIFICATE_REF);
        assert!(
            shop.message
                .contains("does not cover hostname shop.example.com")
        );
        assert_eq!(scope.referenced_certificates().len(), 1);

        scope.expire_tls_secrets(i64::MAX);
        assert!(scope.referenced_certificates().is_empty());
        assert!(
            resolved_refs(&scope, &gw, "api")
                .message
                .contains("the certificate has expired")
        );
    }

    /// The redirect to HTTPS goes to the port of the HTTPS listener that
    /// admits the route.
    #[test]
    fn the_redirect_port_is_that_of_the_listener_admitting_the_route() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        let mut foo = https_listener("foo", None, "foo-tls");
        foo.port = 8443;
        foo.hostname = Some("foo.example.com".into());
        let mut bar = https_listener("bar", None, "bar-tls");
        bar.port = 9443;
        bar.hostname = Some("bar.example.com".into());
        gw.spec.listeners = vec![foo, bar];
        scope.upsert_gateway(&gw);
        store_secret(&scope, "default", "foo-tls", "foo.example.com");
        store_secret(&scope, "default", "bar-tls", "bar.example.com");

        let route = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["foo.example.com".into()],
            vec![parent("gw")],
        );
        assert_eq!(scope.https_redirect_port(&route), Some(8443));
    }

    /// A Secret of another namespace is used once a ReferenceGrant there lets
    /// the Gateway's namespace reference it, and only that Secret when the
    /// grant names one.
    #[test]
    fn a_reference_grant_opens_a_secret_of_another_namespace() {
        use gateway_api::apis::standard::referencegrants::{
            ReferenceGrantFrom, ReferenceGrantSpec, ReferenceGrantTo,
        };
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        gw.spec.listeners = vec![
            https_listener("shared", Some("infra"), "shared-tls"),
            https_listener("other", Some("infra"), "other-tls"),
        ];
        scope.upsert_gateway(&gw);
        store_secret(&scope, "infra", "shared-tls", "shared.example.com");
        store_secret(&scope, "infra", "other-tls", "other.example.com");
        assert_eq!(
            resolved_refs(&scope, &gw, "shared").reason,
            REASON_REF_NOT_PERMITTED
        );

        let grant = |from_kind: &str, name: Option<&str>| ReferenceGrant {
            metadata: ObjectMeta {
                namespace: Some("infra".into()),
                name: Some("certs".into()),
                ..Default::default()
            },
            spec: ReferenceGrantSpec {
                from: vec![ReferenceGrantFrom {
                    group: GATEWAY_API_GROUP.into(),
                    kind: from_kind.into(),
                    namespace: "default".into(),
                }],
                to: vec![ReferenceGrantTo {
                    group: String::new(),
                    kind: "Secret".into(),
                    name: name.map(str::to_string),
                }],
            },
        };
        // A grant for routes does not open Secrets to Gateways.
        scope.upsert_reference_grant(&grant("HTTPRoute", None));
        assert!(scope.referenced_certificates().is_empty());

        scope.upsert_reference_grant(&grant("Gateway", Some("shared-tls")));
        assert_eq!(resolved_refs(&scope, &gw, "shared").status, "True");
        assert_eq!(
            resolved_refs(&scope, &gw, "other").reason,
            REASON_REF_NOT_PERMITTED
        );
        assert_eq!(scope.referenced_certificates().len(), 1);

        scope.upsert_reference_grant(&grant("Gateway", None));
        assert_eq!(scope.referenced_certificates().len(), 2);

        scope.remove_reference_grant(&grant("Gateway", None));
        assert!(scope.referenced_certificates().is_empty());

        // A grant a relist does not bring back no longer opens anything.
        scope.upsert_reference_grant(&grant("Gateway", None));
        assert_eq!(scope.referenced_certificates().len(), 2);
        scope.retain_reference_grants(&[]);
        assert!(scope.referenced_certificates().is_empty());
    }

    /// A backend grant deleted while the watch was down is dropped by the
    /// relist that follows.
    #[test]
    fn a_relist_drops_the_backend_grants_it_does_not_bring_back() {
        let scope = GatewayScope::new();
        let grant = reference_grant("backend", "frontend");
        scope.upsert_reference_grant(&grant);
        assert!(scope.allows_backend_ref("frontend", "backend"));
        scope.retain_reference_grants(std::slice::from_ref(&grant));
        assert!(scope.allows_backend_ref("frontend", "backend"));
        scope.retain_reference_grants(&[]);
        assert!(!scope.allows_backend_ref("frontend", "backend"));
    }

    /// Only an accepted Gateway's certificates are served, and only while
    /// their Secret is there.
    #[test]
    fn certificates_follow_the_gateway_and_its_secrets() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut foreign = gateway("default", "foreign", "someone-else");
        foreign.spec.listeners = vec![https_listener("shop", None, "shop-tls")];
        scope.upsert_gateway(&foreign);
        store_secret(&scope, "default", "shop-tls", "shop.example.com");
        assert!(scope.referenced_certificates().is_empty());

        let mut gw = gateway("default", "gw", "sozune");
        gw.spec.listeners = vec![https_listener("shop", None, "shop-tls")];
        scope.upsert_gateway(&gw);
        assert_eq!(scope.referenced_certificates().len(), 1);

        // A relist of another namespace keeps it.
        scope.retain_tls_secrets(&HashSet::new(), Some("infra"));
        assert_eq!(scope.referenced_certificates().len(), 1);
        scope.retain_tls_secrets(&HashSet::new(), None);
        assert!(scope.referenced_certificates().is_empty());
        store_secret(&scope, "default", "shop-tls", "shop.example.com");
        scope.remove_gateway("default", "gw");
        assert!(scope.referenced_certificates().is_empty());
    }

    /// A Secret that changes rewrites the status of the Gateways that
    /// reference it, and only theirs.
    #[tokio::test]
    async fn a_secret_change_rewrites_the_gateways_referencing_it() {
        let scope = GatewayScope::new();
        let (tx, mut rx) = mpsc::channel(8);
        scope.configure_status(served(), tx);
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut shop = gateway("default", "shop", "sozune");
        shop.spec.listeners = vec![https_listener("tls", None, "shop-tls")];
        scope.upsert_gateway(&shop);
        let mut blog = gateway("default", "blog", "sozune");
        blog.spec.listeners = vec![https_listener("tls", None, "blog-tls")];
        scope.upsert_gateway(&blog);
        while rx.try_recv().is_ok() {}

        let woken = {
            let scope = scope.clone();
            tokio::spawn(async move { scope.changed().await })
        };
        tokio::task::yield_now().await;
        store_secret(&scope, "default", "shop-tls", "shop.example.com");
        // The routes are resolved again: the listener can now serve them.
        tokio::time::timeout(std::time::Duration::from_secs(1), woken)
            .await
            .expect("a Secret change wakes the route watchers")
            .unwrap();
        let written: Vec<String> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|w| match w {
                StatusWrite::Gateway(gw) => gw.metadata.name.unwrap_or_default(),
                StatusWrite::GatewayClass(_) => "class".into(),
            })
            .collect();
        assert_eq!(written, ["shop"]);
    }

    /// The certificate sync hands certificates to the HTTPS worker, retries
    /// what it refuses, replaces one whose chain changed, takes back one no
    /// Gateway references, and leaves a file's certificate alone.
    #[tokio::test]
    async fn certificate_sync_follows_the_scope() {
        use crate::acme::{CertAction, CertCommand};
        use std::time::Duration;

        async fn next(rx: &mut mpsc::Receiver<CertCommand>) -> CertCommand {
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("a certificate command")
                .unwrap()
        }
        fn answer(command: CertCommand, ok: bool) -> CertAction {
            let _ = command.accepted.unwrap().send(ok);
            command.action
        }

        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        gw.spec.listeners = vec![
            https_listener("shop", None, "shop-tls"),
            https_listener("file", None, "file-tls"),
        ];
        scope.upsert_gateway(&gw);
        let shop = store_secret(&scope, "default", "shop-tls", "shop.example.com");
        let file = store_secret(&scope, "default", "file-tls", "file.example.com");

        let (tx, mut rx) = mpsc::channel(8);
        tokio::spawn(super::super::gateway_tls::run_certificate_sync(
            scope.clone(),
            tx,
            HashSet::from([file]),
        ));

        // Refused: sent again on the next change.
        let first = next(&mut rx).await;
        assert_eq!(first.names, ["shop.example.com"]);
        assert_eq!(answer(first, false), CertAction::Add);
        scope.upsert_gateway(&gw);
        assert_eq!(answer(next(&mut rx).await, true), CertAction::Add);

        // The same leaf with another chain is replaced.
        let held = scope.referenced_certificates();
        let held = held.iter().find(|c| c.fingerprint == shop).unwrap();
        let rechained = SecretCertificate {
            names: held.names.clone(),
            cert_pem: held.cert_pem.clone(),
            chain: vec![held.cert_pem.clone()],
            key_pem: held.key_pem.clone(),
            fingerprint: held.fingerprint.clone(),
            not_after: held.not_after,
        };
        scope.upsert_tls_secret(
            ("default".into(), "shop-tls".into()),
            Ok(Arc::new(rechained)),
        );
        assert_eq!(answer(next(&mut rx).await, true), CertAction::Replace);

        // No Gateway references it any more: taken back.
        scope.remove_gateway("default", "gw");
        let removed = next(&mut rx).await;
        assert_eq!(removed.names, ["shop.example.com"]);
        assert_eq!(answer(removed, true), CertAction::Remove);
        // The file's certificate was never sent.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .is_err()
        );
    }

    /// A route is served over HTTPS for the hostnames its HTTPS listeners
    /// admit, over HTTP for those its HTTP listeners admit, and over both for
    /// those both admit.
    #[test]
    fn route_entrypoints_follow_the_scheme_of_their_listeners() {
        let route = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent("gw")],
        );
        let host = |hosts: &[&str]| Some(hosts.iter().map(|h| h.to_string()).collect());
        let schemes = |plain, secure| -> Vec<(String, Vec<String>, bool, bool)> {
            route_entrypoints_by_scheme(&route, &r1(), &AllowAllBackendRefs, plain, secure, None)
                .into_iter()
                .map(|ep| {
                    (
                        ep.id,
                        ep.config.hostnames,
                        ep.config.tls,
                        ep.config.https_redirect,
                    )
                })
                .collect()
        };
        let id = format!("{SOURCE_TAG}-default-web-0");

        assert_eq!(
            schemes(host(&["a.example.com"]), None),
            [(id.clone(), vec!["a.example.com".to_string()], false, false)]
        );
        assert_eq!(
            schemes(None, host(&["a.example.com"])),
            [(
                format!("{id}-https"),
                vec!["a.example.com".to_string()],
                true,
                true
            )]
        );
        assert_eq!(
            schemes(
                host(&["a.example.com", "b.example.com"]),
                host(&["a.example.com", "c.example.com"])
            ),
            [
                (id.clone(), vec!["b.example.com".to_string()], false, false),
                (
                    format!("{id}-tls"),
                    vec!["a.example.com".to_string()],
                    true,
                    false
                ),
                (
                    format!("{id}-https"),
                    vec!["c.example.com".to_string()],
                    true,
                    true
                ),
            ]
        );
        // A wildcard on one side covers the exact names of the other.
        assert_eq!(
            schemes(host(&["*.example.com"]), host(&["api.example.com"])),
            [
                (id.clone(), vec!["*.example.com".to_string()], false, false),
                (
                    format!("{id}-tls"),
                    vec!["api.example.com".to_string()],
                    true,
                    false
                ),
            ]
        );
        assert_eq!(
            schemes(host(&["api.example.com"]), host(&["*.example.com"])),
            [
                (
                    format!("{id}-tls"),
                    vec!["api.example.com".to_string()],
                    true,
                    false
                ),
                (
                    format!("{id}-https"),
                    vec!["*.example.com".to_string()],
                    true,
                    true
                ),
            ]
        );
        // A listener admitting every host admits the other scheme's names.
        assert_eq!(
            schemes(Some(Vec::new()), host(&["a.example.com"])),
            [
                (
                    format!("{id}-tls"),
                    vec!["a.example.com".to_string()],
                    true,
                    false
                ),
                (id.clone(), Vec::new(), false, false),
            ]
        );
        assert_eq!(
            schemes(host(&["a.example.com"]), Some(Vec::new())),
            [
                (
                    format!("{id}-tls"),
                    vec!["a.example.com".to_string()],
                    true,
                    false
                ),
                (format!("{id}-https"), Vec::new(), true, true),
            ]
        );
    }

    /// An HTTPRoute attaches through an HTTPS listener, and is served over
    /// HTTPS on the names that listener admits.
    #[test]
    fn an_httproute_attaches_through_an_https_listener() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        let mut https = https_listener("tls", None, "shop-tls");
        https.hostname = Some("*.shop.example".into());
        gw.spec.listeners = vec![gw_listener("http", 80, "HTTP"), https];
        scope.upsert_gateway(&gw);

        let route = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["www.shop.example".into(), "blog.example".into()],
            vec![parent("gw")],
        );
        assert!(scope.accepts_route(&route));
        // Not over HTTPS until the listener has a certificate to serve.
        assert_eq!(
            scope.effective_hostnames_for_route(&route, GatewayScope::listener_serves_https),
            None
        );
        store_secret(&scope, "default", "shop-tls", "*.shop.example");
        assert_eq!(
            scope.effective_hostnames_for_route(&route, GatewayScope::listener_serves_https),
            Some(vec!["www.shop.example".to_string()])
        );
        assert_eq!(
            scope.effective_hostnames_for_route(&route, GatewayScope::listener_is_plain_http),
            Some(vec![
                "www.shop.example".to_string(),
                "blog.example".to_string()
            ])
        );

        // Redirected to the default HTTPS port: the listener is on 443.
        assert_eq!(scope.https_redirect_port(&route), None);
        let mut on_8443 = gw.clone();
        on_8443.spec.listeners[1].port = 8443;
        scope.upsert_gateway(&on_8443);
        assert_eq!(scope.https_redirect_port(&route), Some(8443));
        scope.upsert_gateway(&gw);

        // Through the HTTPS listener alone, nothing is served over HTTP.
        let mut only_https = route.clone();
        only_https.spec.parent_refs.as_mut().unwrap()[0].section_name = Some("tls".into());
        assert_eq!(
            scope.effective_hostnames_for_route(&only_https, GatewayScope::listener_is_plain_http),
            None
        );
    }

    #[test]
    fn listener_status_reflects_allowed_route_kinds() {
        let gw = gateway("default", "gw", "sozune");
        let status = |kinds: &[&str]| {
            let mut listener = li("l", 80, None);
            listener.allowed_kinds = Some(kinds.iter().map(|k| k.to_string()).collect());
            build_listener_status(&gw, &listener, &served(), 0, None)
        };

        let http_only = status(&["HTTPRoute"]);
        assert_eq!(http_only.supported_kinds.len(), 1);
        assert_eq!(
            condition_of(&http_only, CONDITION_TYPE_PROGRAMMED).status,
            "True"
        );
        assert_eq!(
            condition_of(&http_only, CONDITION_TYPE_RESOLVED_REFS).status,
            "True"
        );

        let mixed = status(&["HTTPRoute", "GRPCRoute"]);
        assert_eq!(mixed.supported_kinds.len(), 1);
        assert_eq!(
            condition_of(&mixed, CONDITION_TYPE_PROGRAMMED).status,
            "True"
        );
        let resolved = condition_of(&mixed, CONDITION_TYPE_RESOLVED_REFS);
        assert_eq!(resolved.status, "False");
        assert_eq!(resolved.reason, REASON_INVALID_ROUTE_KINDS);

        let grpc_only = status(&["GRPCRoute"]);
        assert!(grpc_only.supported_kinds.is_empty());
        assert_eq!(
            condition_of(&grpc_only, CONDITION_TYPE_PROGRAMMED).status,
            "False"
        );
        assert_eq!(
            condition_of(&grpc_only, CONDITION_TYPE_RESOLVED_REFS).reason,
            REASON_INVALID_ROUTE_KINDS
        );
    }

    #[test]
    fn listener_status_follows_how_sozune_routes() {
        let gw = gateway("default", "gw", "sozune");
        let status = |port: i32, protocol: &str| {
            let listener = ListenerInfo {
                name: "l".into(),
                port,
                hostname: None,
                protocol: protocol.into(),
                tls_mode: None,
                allowed_namespaces: AllowedNamespaces::Same,
                allowed_kinds: None,
            };
            build_listener_status(&gw, &listener, &served(), 0, None)
        };

        let http = status(80, "HTTP");
        assert_eq!(
            condition_of(&http, CONDITION_TYPE_PROGRAMMED).status,
            "True"
        );
        assert_eq!(http.supported_kinds[0].kind, "HTTPRoute");

        // An HTTP listener is served whatever its port, on Sōzune's.
        let other = status(8080, "HTTP");
        let programmed = condition_of(&other, CONDITION_TYPE_PROGRAMMED);
        assert_eq!(programmed.status, "True");
        assert!(programmed.message.contains("port 80"));
        // An HTTPS listener terminates TLS on Sōzune's HTTPS port.
        let https = status(8443, "HTTPS");
        let programmed = condition_of(&https, CONDITION_TYPE_PROGRAMMED);
        assert_eq!(programmed.status, "True");
        assert!(programmed.message.contains("port 443"));
        assert_eq!(https.supported_kinds[0].kind, "HTTPRoute");
        // Passthrough is for TLS listeners.
        let passthrough = ListenerInfo {
            name: "l".into(),
            port: 8443,
            hostname: None,
            protocol: "HTTPS".into(),
            tls_mode: Some(GatewayListenersTlsMode::Passthrough),
            allowed_namespaces: AllowedNamespaces::Same,
            allowed_kinds: None,
        };
        let passthrough = build_listener_status(&gw, &passthrough, &served(), 0, None);
        assert_eq!(
            condition_of(&passthrough, CONDITION_TYPE_ACCEPTED).reason,
            REASON_UNSUPPORTED_PROTOCOL
        );
        assert!(passthrough.supported_kinds.is_empty());

        assert_eq!(
            condition_of(&status(5432, "TCP"), CONDITION_TYPE_PROGRAMMED).status,
            "True"
        );
        assert_eq!(
            condition_of(&status(5433, "TCP"), CONDITION_TYPE_ACCEPTED).reason,
            REASON_PORT_UNAVAILABLE
        );
        assert_eq!(
            condition_of(&status(53, "UDP"), CONDITION_TYPE_PROGRAMMED).status,
            "True"
        );
        // A port of `gateway_ports` is served without a declared listener.
        assert_eq!(
            condition_of(&status(9050, "TCP"), CONDITION_TYPE_PROGRAMMED).status,
            "True"
        );
        assert_eq!(
            condition_of(&status(5353, "UDP"), CONDITION_TYPE_PROGRAMMED).status,
            "True"
        );
        assert_eq!(
            condition_of(&status(5353, "TCP"), CONDITION_TYPE_ACCEPTED).reason,
            REASON_PORT_UNAVAILABLE
        );

        let grpc = status(80, "GRPC");
        assert_eq!(
            condition_of(&grpc, CONDITION_TYPE_ACCEPTED).reason,
            REASON_UNSUPPORTED_PROTOCOL
        );
        assert!(grpc.supported_kinds.is_empty());
    }

    /// A port of `gateway_ports` the proxy could not open is not served.
    #[test]
    fn listener_status_reports_a_port_that_could_not_be_opened() {
        let gw = gateway("default", "gw", "sozune");
        let listener = ListenerInfo {
            name: "l".into(),
            port: 9050,
            hostname: None,
            protocol: "TCP".into(),
            tls_mode: None,
            allowed_namespaces: AllowedNamespaces::Same,
            allowed_kinds: None,
        };
        let mut served = served();
        served
            .unopened
            .tcp
            .insert(9050, "Address already in use".into());

        let status = build_listener_status(&gw, &listener, &served, 1, None);
        let programmed = condition_of(&status, CONDITION_TYPE_PROGRAMMED);
        assert_eq!(programmed.status, "False");
        assert!(programmed.message.contains("Address already in use"));
        assert_eq!(
            condition_of(&status, CONDITION_TYPE_ACCEPTED).reason,
            REASON_PORT_UNAVAILABLE
        );
        // Only the port that failed.
        served.unopened.tcp.clear();
        served.unopened.udp.insert(9050, "taken".into());
        let status = build_listener_status(&gw, &listener, &served, 1, None);
        assert_eq!(
            condition_of(&status, CONDITION_TYPE_PROGRAMMED).status,
            "True"
        );
    }

    /// `attachedRoutes` counts the routes whose parentRefs select a listener
    /// that carries their kind, and drops a deleted route.
    /// A route only attaches to a listener whose hostname admits one of its
    /// own.
    #[test]
    fn a_route_does_not_attach_to_a_listener_refusing_its_hostnames() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        let mut shop = gw_listener("shop", 80, "HTTP");
        shop.hostname = Some("*.shop.example".into());
        let mut blog = gw_listener("blog", 8080, "HTTP");
        blog.hostname = Some("blog.example".into());
        gw.spec.listeners = vec![shop, blog];
        scope.upsert_gateway(&gw);

        scope.record_attachments(
            "HTTPRoute",
            "r1",
            "default",
            &["www.shop.example".to_string()],
            &[parent("gw")],
            GatewayScope::listener_serves_http,
        );
        let counts: Vec<(String, i32)> = scope
            .listener_statuses(&gw)
            .into_iter()
            .map(|l| (l.name, l.attached_routes))
            .collect();
        assert_eq!(counts, [("shop".to_string(), 1), ("blog".to_string(), 0)]);
    }

    /// A port the proxy could not open rewrites the status of the Gateways
    /// listening on it, and only theirs.
    #[tokio::test]
    async fn an_unopened_port_rewrites_the_gateways_on_it() {
        let scope = GatewayScope::new();
        let (tx, mut rx) = mpsc::channel(8);
        scope.configure_status(served(), tx);
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut on_port = gateway("default", "on-port", "sozune");
        on_port.spec.listeners = vec![gw_listener("tcp", 9050, "TCP")];
        scope.upsert_gateway(&on_port);
        let mut elsewhere = gateway("default", "elsewhere", "sozune");
        elsewhere.spec.listeners = vec![gw_listener("tcp", 9060, "TCP")];
        scope.upsert_gateway(&elsewhere);
        while rx.try_recv().is_ok() {}

        let mut ports = crate::proxy::backend::UnopenedGatewayPorts::default();
        ports.tcp.insert(9050, "Address already in use".into());
        scope.set_unopened_ports(ports.clone()).await;
        let written: Vec<String> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|w| match w {
                StatusWrite::Gateway(gw) => gw.metadata.name.unwrap_or_default(),
                StatusWrite::GatewayClass(_) => "class".into(),
            })
            .collect();
        assert_eq!(written, ["on-port"]);
        let statuses = scope.listener_statuses(&on_port);
        let programmed = condition_of(&statuses[0], CONDITION_TYPE_PROGRAMMED);
        assert_eq!(programmed.status, "False");

        // Nothing changed: nothing to rewrite.
        scope.set_unopened_ports(ports).await;
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn attached_routes_are_counted_per_listener() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        gw.spec.listeners = vec![
            gw_listener("web", 80, "HTTP"),
            gw_listener("admin", 8080, "HTTP"),
            gw_listener("db", 5432, "TCP"),
        ];
        scope.upsert_gateway(&gw);

        let mut web_only = parent("gw");
        web_only.section_name = Some("web".into());
        scope.record_attachments(
            "HTTPRoute",
            "r1",
            "default",
            &[],
            &[web_only],
            GatewayScope::listener_serves_http,
        );
        scope.record_attachments(
            "HTTPRoute",
            "r2",
            "default",
            &[],
            &[parent("gw")],
            GatewayScope::listener_serves_http,
        );
        let counts = |scope: &GatewayScope| -> Vec<(String, i32)> {
            scope
                .listener_statuses(&gw)
                .into_iter()
                .map(|l| (l.name, l.attached_routes))
                .collect()
        };

        // r1 on web; r2 on both HTTP listeners, never on the TCP one.
        assert_eq!(
            counts(&scope),
            [
                ("web".to_string(), 2),
                ("admin".to_string(), 1),
                ("db".to_string(), 0)
            ]
        );

        scope.forget_attachments("HTTPRoute", "r2");
        assert_eq!(
            counts(&scope),
            [
                ("web".to_string(), 1),
                ("admin".to_string(), 0),
                ("db".to_string(), 0)
            ]
        );
    }

    /// A TLS listener that terminates carries no TLSRoute: it is not ready,
    /// whatever its port.
    #[test]
    fn a_terminating_tls_listener_is_not_programmed() {
        let gw = gateway("default", "gw", "sozune");
        let terminate = li_tls("tls", 5432, None, GatewayListenersTlsMode::Terminate);
        let passthrough = li_tls("tls", 5432, None, GatewayListenersTlsMode::Passthrough);

        let status = build_listener_status(&gw, &terminate, &served(), 0, None);
        let accepted = condition_of(&status, CONDITION_TYPE_ACCEPTED);
        assert_eq!(accepted.status, "False");
        assert_eq!(accepted.reason, REASON_UNSUPPORTED_PROTOCOL);
        assert!(accepted.message.contains("Passthrough"));
        assert!(status.supported_kinds.is_empty());

        let status = build_listener_status(&gw, &passthrough, &served(), 0, None);
        assert_eq!(
            condition_of(&status, CONDITION_TYPE_PROGRAMMED).status,
            "True"
        );
    }

    /// A condition whose status stays keeps its transition time, even when
    /// its generation or message moves on.
    #[test]
    fn a_condition_keeps_its_transition_time_until_its_status_changes() {
        let at = |secs| Time(k8s_openapi::chrono::DateTime::from_timestamp(secs, 0).unwrap());
        let condition = |status: &str, generation, time| Condition {
            type_: "Accepted".into(),
            status: status.into(),
            reason: "Accepted".into(),
            message: String::new(),
            last_transition_time: time,
            observed_generation: Some(generation),
        };
        let previous = vec![condition("True", 1, at(1_000))];

        let (merged, changed) =
            merge_conditions(Some(&previous), vec![condition("True", 2, at(2_000))]);
        assert!(changed, "a new generation is written");
        assert_eq!(merged[0].last_transition_time, at(1_000));
        assert_eq!(merged[0].observed_generation, Some(2));

        let (merged, _) = merge_conditions(Some(&previous), vec![condition("False", 2, at(2_000))]);
        assert_eq!(merged[0].last_transition_time, at(2_000));
    }

    /// A route deleted while the watcher was away gets no Delete event: the
    /// relist that follows drops it, its entrypoints and its attachments.
    #[test]
    fn a_route_missing_from_a_relist_is_dropped() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        gw.spec.listeners = vec![gw_listener("web", 80, "HTTP")];
        scope.upsert_gateway(&gw);

        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));
        let mut kept = route_with(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
        );
        kept.metadata.uid = Some("kept".into());
        kept.metadata.name = Some("kept".into());
        let mut gone = kept.clone();
        gone.metadata.uid = Some("gone".into());
        gone.metadata.name = Some("gone".into());
        gone.spec.hostnames = Some(vec!["b.example.com".into()]);
        apply_route(&kept, &storage, &index, &r1(), &scope, None);
        apply_route(&gone, &storage, &index, &r1(), &scope, None);
        assert_eq!(scope.listener_statuses(&gw)[0].attached_routes, 2);
        let before = storage.read().unwrap().len();

        let changed = drop_routes_not_relisted(
            "HTTPRoute",
            &HashSet::from(["kept".to_string()]),
            &index,
            |t: &TrackedRoute| t.entrypoint_ids.as_slice(),
            &storage,
            &scope,
        );

        assert!(changed);
        assert!(index.read().unwrap().contains_key("kept"));
        assert!(!index.read().unwrap().contains_key("gone"));
        assert!(storage.read().unwrap().len() < before);
        assert_eq!(scope.listener_statuses(&gw)[0].attached_routes, 1);
    }

    /// A route deleted and created again under the same name while the
    /// watcher was away comes back with a new uid but the same entrypoint
    /// ids: dropping the old uid must leave the new route's entrypoints.
    #[test]
    fn a_route_recreated_under_its_name_keeps_its_entrypoints() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        gw.spec.listeners = vec![gw_listener("web", 80, "HTTP")];
        scope.upsert_gateway(&gw);
        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));
        let mut old = route_with(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
        );
        old.metadata.uid = Some("old".into());
        apply_route(&old, &storage, &index, &r1(), &scope, None);
        let mut recreated = old.clone();
        recreated.metadata.uid = Some("new".into());
        apply_route(&recreated, &storage, &index, &r1(), &scope, None);
        let installed = storage.read().unwrap().len();
        assert!(installed > 0);

        drop_routes_not_relisted(
            "HTTPRoute",
            &HashSet::from(["new".to_string()]),
            &index,
            |t: &TrackedRoute| t.entrypoint_ids.as_slice(),
            &storage,
            &scope,
        );

        assert!(!index.read().unwrap().contains_key("old"));
        assert_eq!(storage.read().unwrap().len(), installed);
    }

    /// An unchanged listener keeps the time its conditions last changed.
    #[test]
    fn unchanged_listener_conditions_keep_their_transition_time() {
        let gw = gateway("default", "gw", "sozune");
        let listener = li("web", 80, None);
        let mut previous = build_listener_status(&gw, &listener, &served(), 1, None);
        for condition in &mut previous.conditions {
            condition.last_transition_time =
                Time(k8s_openapi::chrono::DateTime::from_timestamp(1_000, 0).unwrap());
        }

        let (merged, changed) = merge_listener_statuses(
            Some(std::slice::from_ref(&previous)),
            vec![build_listener_status(&gw, &listener, &served(), 1, None)],
        );
        assert!(!changed);
        assert_eq!(merged[0].conditions, previous.conditions);

        let (_, changed) = merge_listener_statuses(
            Some(std::slice::from_ref(&previous)),
            vec![build_listener_status(&gw, &listener, &served(), 2, None)],
        );
        assert!(changed, "a new attached route is a change");
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

        // Naming `infra/gw` reaches the Gateway, whose listener only admits
        // routes of its own namespace by default.
        r.spec.parent_refs = Some(vec![HTTPRouteParentRefs {
            name: "gw".into(),
            namespace: Some("infra".into()),
            ..Default::default()
        }]);
        assert!(!scope.accepts_route(&r));

        // Once the listener admits every namespace, the route is accepted.
        let mut gw = gateway("infra", "gw", "sozune");
        gw.spec.listeners[0].allowed_routes = Some(allowed_from(
            GatewayListenersAllowedRoutesNamespacesFrom::All,
        ));
        scope.upsert_gateway(&gw);
        assert!(scope.accepts_route(&r));
    }

    fn allowed_from(
        from: GatewayListenersAllowedRoutesNamespacesFrom,
    ) -> GatewayListenersAllowedRoutes {
        GatewayListenersAllowedRoutes {
            namespaces: Some(GatewayListenersAllowedRoutesNamespaces {
                from: Some(from),
                selector: None,
            }),
            kinds: None,
        }
    }

    fn allowed_kind(group: Option<&str>, kind: &str) -> GatewayListenersAllowedRoutes {
        GatewayListenersAllowedRoutes {
            namespaces: None,
            kinds: Some(vec![GatewayListenersAllowedRoutesKinds {
                group: group.map(Into::into),
                kind: kind.into(),
            }]),
        }
    }

    /// Namespace labels are not watched, so a selector admits nothing — even
    /// a route of the Gateway's own namespace.
    #[test]
    fn a_namespace_selector_admits_no_route() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        gw.spec.listeners[0].allowed_routes = Some(allowed_from(
            GatewayListenersAllowedRoutesNamespacesFrom::Selector,
        ));
        scope.upsert_gateway(&gw);

        let r = route_with(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
        );
        assert!(!scope.accepts_route(&r));
    }

    /// A listener of another protocol that admits every namespace does not
    /// open the Gateway to HTTPRoutes its HTTP listener refuses.
    #[test]
    fn an_httproute_only_attaches_through_http_listeners() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("infra", "gw", "sozune");
        let mut raw = gw_listener("raw", 9000, "TCP");
        raw.allowed_routes = Some(allowed_from(
            GatewayListenersAllowedRoutesNamespacesFrom::All,
        ));
        gw.spec.listeners.push(raw);
        scope.upsert_gateway(&gw);

        let mut r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![HTTPRouteParentRefs {
                name: "gw".into(),
                namespace: Some("infra".into()),
                ..Default::default()
            }],
        );
        r.metadata.namespace = Some("apps".into());
        assert!(!scope.accepts_route(&r));
        let parents = build_route_status(&r, &scope, RouteOutcome::NotMine);
        assert_eq!(parents.len(), 1);
        assert_eq!(
            parents[0].conditions.as_deref().unwrap_or_default()[0].reason,
            REASON_NOT_ALLOWED_BY_LISTENERS
        );
    }

    /// A Gateway of ours that refuses a parentRef says why in the route's
    /// status, instead of leaving no entry behind.
    #[test]
    fn a_refused_parent_reports_why() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        gw.spec.listeners = vec![gw_listener("raw", 9000, "TCP")];
        scope.upsert_gateway(&gw);
        let reason_for = |parent_ref: HTTPRouteParentRefs| {
            let r = route_with_uid_parents(
                "uid-1",
                vec![rule(None, vec![backend("api", 80)])],
                vec!["a.example.com".into()],
                vec![parent_ref],
            );
            assert!(!scope.accepts_route(&r));
            let parents = build_route_status(&r, &scope, RouteOutcome::NotMine);
            assert_eq!(parents.len(), 1);
            parents[0].conditions.as_deref().unwrap_or_default()[0]
                .reason
                .clone()
        };

        // Only a TCP listener: nothing carries an HTTPRoute.
        assert_eq!(reason_for(parent("gw")), REASON_NOT_ALLOWED_BY_LISTENERS);
        let mut missing = parent("gw");
        missing.section_name = Some("web".into());
        assert_eq!(reason_for(missing), REASON_NO_MATCHING_PARENT);
    }

    #[test]
    fn allowed_route_kinds_narrow_what_attaches() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let r = route_with(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
        );
        let accepts_with = |allowed: GatewayListenersAllowedRoutes| {
            let mut gw = gateway("default", "gw", "sozune");
            gw.spec.listeners[0].allowed_routes = Some(allowed);
            scope.upsert_gateway(&gw);
            scope.accepts_route(&r)
        };

        assert!(accepts_with(allowed_kind(None, "HTTPRoute")));
        assert!(accepts_with(allowed_kind(
            Some(GATEWAY_API_GROUP),
            "HTTPRoute"
        )));
        assert!(!accepts_with(allowed_kind(None, "GRPCRoute")));
        assert!(!accepts_with(allowed_kind(
            Some("example.com"),
            "HTTPRoute"
        )));
        // An empty list leaves the choice to the protocol.
        assert!(accepts_with(GatewayListenersAllowedRoutes {
            namespaces: None,
            kinds: Some(Vec::new()),
        }));
    }

    /// A route from another namespace only gets the ports, and only counts
    /// on the listeners, that admit its namespace.
    #[test]
    fn a_cross_namespace_route_only_binds_listeners_that_admit_it() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("infra", "gw", "sozune");
        let mut open = gw_listener("open", 9000, "TCP");
        open.allowed_routes = Some(allowed_from(
            GatewayListenersAllowedRoutesNamespacesFrom::All,
        ));
        gw.spec.listeners = vec![open, gw_listener("own", 9001, "TCP")];
        scope.upsert_gateway(&gw);

        let mut route = tcp_route(9000);
        route.metadata.namespace = Some("apps".into());
        route.spec.parent_refs = Some(vec![TCPRouteParentRefs {
            name: "gw".into(),
            namespace: Some("infra".into()),
            ..Default::default()
        }]);
        assert!(scope.accepts_tcp_route(&route));
        assert_eq!(
            scope
                .effective_tcp_ports(&route)
                .into_iter()
                .collect::<Vec<_>>(),
            [9000]
        );

        scope.record_attachments(
            "TCPRoute",
            "uid-tcp-1",
            "apps",
            &[],
            route.spec.parent_refs.as_deref().unwrap_or_default(),
            GatewayScope::listener_serves_tcp,
        );
        let counts: Vec<(String, i32)> = scope
            .listener_statuses(&gw)
            .into_iter()
            .map(|l| (l.name, l.attached_routes))
            .collect();
        assert_eq!(counts, [("open".to_string(), 1), ("own".to_string(), 0)]);

        // Naming the listener that refuses it binds nothing.
        route.spec.parent_refs = Some(vec![TCPRouteParentRefs {
            name: "gw".into(),
            namespace: Some("infra".into()),
            section_name: Some("own".into()),
            ..Default::default()
        }]);
        assert!(!scope.accepts_tcp_route(&route));
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
