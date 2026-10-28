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
    Backend, Entrypoint, EntrypointConfig, HeaderConfig, LoadBalancer, Mirror, PathConfig,
    PathRewrite, PathRuleType, Protocol, UrlRewrite,
};
use futures_util::StreamExt;
use gateway_api::apis::experimental::tcproutes::{
    TCPRoute, TCPRouteParentRefs, TCPRouteRules, TCPRouteStatusParents,
    TCPRouteStatusParentsParentRef,
};
use gateway_api::apis::experimental::tlsroutes::{
    TLSRoute, TLSRouteParentRefs, TLSRouteRules, TLSRouteStatusParents,
    TLSRouteStatusParentsParentRef,
};
use gateway_api::apis::experimental::udproutes::{
    UDPRoute, UDPRouteParentRefs, UDPRouteRules, UDPRouteStatusParents,
    UDPRouteStatusParentsParentRef,
};
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::{
    Gateway, GatewayListeners, GatewayListenersAllowedRoutesNamespacesFrom,
    GatewayListenersTlsCertificateRefs, GatewayListenersTlsMode, GatewayStatusAddresses,
};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HTTPRouteParentRefs, HTTPRouteRules, HTTPRouteRulesBackendRefs,
    HTTPRouteRulesFilters, HTTPRouteRulesMatches, HTTPRouteRulesMatchesPathType, HTTPRouteStatus,
    HTTPRouteStatusParents, HTTPRouteStatusParentsParentRef,
};
use gateway_api::apis::standard::referencegrants::ReferenceGrant;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use kube::api::{Patch, PatchParams};
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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

/// How long a Gateway status write that failed waits before it is tried
/// again.
const STATUS_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(30);

/// How long one status write may take. The client's own read timeout is
/// sized for watches, minutes long, and a write stuck that long would hold
/// back every write queued behind it.
const STATUS_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// `write`, given up past [`STATUS_WRITE_TIMEOUT`] as a failed write.
pub(crate) async fn bounded_status_write<T>(
    write: impl std::future::Future<Output = Result<T, kube::Error>>,
) -> Result<T, kube::Error> {
    tokio::time::timeout(STATUS_WRITE_TIMEOUT, write)
        .await
        .unwrap_or_else(|elapsed| Err(kube::Error::Service(Box::new(elapsed))))
}

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllowedNamespaces {
    /// Only routes in the Gateway's own namespace (the API default).
    Same,
    /// Routes in any namespace.
    All,
    /// Routes in namespaces whose labels match the selector. `None` when the
    /// listener gives none, or one Sōzune cannot read: no route is admitted
    /// then, rather than more than meant.
    Selector(Option<NamespaceSelector>),
}

/// A label selector over namespaces, as `allowedRoutes.namespaces.selector`
/// writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceSelector {
    match_labels: BTreeMap<String, String>,
    match_expressions: Vec<(String, SelectorOperator, Vec<String>)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectorOperator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

impl NamespaceSelector {
    fn of(
        selector: &gateway_api::apis::standard::gateways::GatewayListenersAllowedRoutesNamespacesSelector,
    ) -> Option<Self> {
        let match_expressions = selector
            .match_expressions
            .iter()
            .flatten()
            .map(|e| {
                let values = e.values.clone().unwrap_or_default();
                // As Kubernetes has it: `In` and `NotIn` need values, the
                // others none. Read otherwise, `NotIn` with no value would
                // match every namespace.
                let operator = match e.operator.as_str() {
                    "In" if !values.is_empty() => SelectorOperator::In,
                    "NotIn" if !values.is_empty() => SelectorOperator::NotIn,
                    "Exists" if values.is_empty() => SelectorOperator::Exists,
                    "DoesNotExist" if values.is_empty() => SelectorOperator::DoesNotExist,
                    _ => return None,
                };
                Some((e.key.clone(), operator, values))
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            match_labels: selector.match_labels.clone().unwrap_or_default(),
            match_expressions,
        })
    }

    /// Whether a namespace with `labels` matches. An empty selector matches
    /// every namespace, as in Kubernetes.
    fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        self.match_labels
            .iter()
            .all(|(k, v)| labels.get(k) == Some(v))
            && self.match_expressions.iter().all(|(key, op, values)| {
                let value = labels.get(key);
                match op {
                    SelectorOperator::In => value.is_some_and(|v| values.contains(v)),
                    SelectorOperator::NotIn => value.is_none_or(|v| !values.contains(v)),
                    SelectorOperator::Exists => value.is_some(),
                    SelectorOperator::DoesNotExist => value.is_none(),
                }
            })
    }
}

impl ListenerInfo {
    /// True iff this listener's `allowedRoutes` lets a `kind` route from
    /// `route_ns` attach to it, on a Gateway in `gateway_ns`, the namespaces
    /// having `namespace_labels`.
    pub(crate) fn admits(
        &self,
        gateway_ns: &str,
        route_ns: &str,
        kind: &str,
        namespace_labels: &HashMap<String, BTreeMap<String, String>>,
    ) -> bool {
        let namespace_ok = match &self.allowed_namespaces {
            AllowedNamespaces::Same => route_ns == gateway_ns,
            AllowedNamespaces::All => true,
            AllowedNamespaces::Selector(selector) => selector.as_ref().is_some_and(|s| {
                namespace_labels
                    .get(route_ns)
                    .is_some_and(|labels| s.matches(labels))
            }),
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
    /// Cross-namespace backendRef authorisations: what each ReferenceGrant,
    /// keyed by its namespace and name, lets routes reference among the
    /// Services of its namespace. Same-namespace refs never need a grant.
    reference_grants: HashMap<(String, String), ServiceGrant>,
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
    /// The labels of each namespace, for `allowedRoutes.namespaces.selector`.
    namespace_labels: HashMap<String, BTreeMap<String, String>>,
    /// Sōzune's addresses, as `(type, value)`, for the `status.addresses` of
    /// the Gateways it owns. `None` leaves them alone: neither
    /// `publish_service` nor `publish_addresses` is set.
    addresses: Option<Vec<(String, String)>>,
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
    /// Whether a `TLS` listener on the HTTPS port is served, by its
    /// passthrough listener (`proxy.https.passthrough`).
    pub https_passthrough: bool,
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
            https_passthrough: proxy.https.passthrough,
            gateway: proxy.gateway_ports.clone(),
            unopened: Default::default(),
        }
    }

    /// The port an HTTP listener on `port` is served on when it is its own:
    /// a port of `gateway.http` other than the main HTTP one. `None` serves it
    /// on the main HTTP port.
    pub fn own_http_port(&self, port: i32) -> Option<u16> {
        u16::try_from(port)
            .ok()
            .filter(|p| *p != self.http && self.gateway.allows_http(*p))
    }

    /// Why an HTTP listener on `port` is not served, if it is not: one on a
    /// port of its own that could not be opened.
    fn http_problem(&self, port: i32) -> Option<String> {
        let p = self.own_http_port(port)?;
        self.unopened
            .http
            .get(&p)
            .map(|e| format!("Sōzune could not open port {p}: {e}"))
    }

    /// The HTTPS twin of [`Self::own_http_port`], over `gateway.https`.
    pub fn own_https_port(&self, port: i32) -> Option<u16> {
        u16::try_from(port)
            .ok()
            .filter(|p| *p != self.https && self.gateway.allows_https(*p))
    }

    /// The HTTPS twin of [`Self::http_problem`].
    fn https_problem(&self, port: i32) -> Option<String> {
        let p = self.own_https_port(port)?;
        self.unopened
            .https
            .get(&p)
            .map(|e| format!("Sōzune could not open port {p}: {e}"))
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
                .filter(|l| {
                    listener_ok(l) && l.admits(&ns, route_namespace, kind, &g.namespace_labels)
                })
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
            let http = changed(&g.served.unopened.http, &ports.http);
            let https = changed(&g.served.unopened.https, &ports.https);
            let tcp = changed(&g.served.unopened.tcp, &ports.tcp);
            let udp = changed(&g.served.unopened.udp, &ports.udp);
            g.served.unopened = ports;
            let affected = |listener: &ListenerInfo| {
                let Ok(port) = u16::try_from(listener.port) else {
                    return false;
                };
                match listener.protocol.to_ascii_uppercase().as_str() {
                    "HTTP" => http.contains(&port),
                    "HTTPS" => https.contains(&port),
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
            .filter(|l| {
                listener_ok(l) && l.admits(ns, route_namespace, route_kind, &g.namespace_labels)
            })
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
                        .filter(|l| l.admits(ns, route_namespace, route_kind, &g.namespace_labels))
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
        let mut by_port: BTreeMap<i32, Vec<String>> = BTreeMap::new();
        for p in route
            .spec
            .parent_refs
            .iter()
            .flatten()
            .filter(|p| self.accepts_tls_parent_ref(route_ns, p))
        {
            for (port, hostnames) in self.tls_parent_hostnames_by_port(route, p) {
                let entry = by_port.entry(port).or_default();
                for h in hostnames {
                    if !entry.contains(&h) {
                        entry.push(h);
                    }
                }
            }
        }
        by_port
    }

    /// [`Self::effective_tls_hostnames_by_port`] through the listeners one
    /// `parentRef` selects.
    fn tls_parent_hostnames_by_port(
        &self,
        route: &TLSRoute,
        p: &TLSRouteParentRefs,
    ) -> BTreeMap<i32, Vec<String>> {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let route_hostnames = route.spec.hostnames.clone().unwrap_or_default();
        let mut by_port: BTreeMap<i32, Vec<String>> = BTreeMap::new();
        {
            let ns = p.namespace.as_deref().unwrap_or(route_ns);
            let Some(listeners) = self.gateway_listeners(ns, &p.name, route_ns, "TLSRoute") else {
                return by_port;
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
                        .filter(|l| l.admits(ns, route_ns, kind, &g.namespace_labels))
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
        listener_ok: &dyn Fn(&ListenerInfo) -> bool,
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

    /// The port an HTTP listener is served on when it is its own (see
    /// [`ServedPorts::own_http_port`]).
    fn own_http_port(&self, listener: &ListenerInfo) -> Option<u16> {
        match self.state.read() {
            Ok(g) => g.served.own_http_port(listener.port),
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                None
            }
        }
    }

    /// The HTTPS twin of [`Self::own_http_port`].
    fn own_https_port(&self, listener: &ListenerInfo) -> Option<u16> {
        match self.state.read() {
            Ok(g) => g.served.own_https_port(listener.port),
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                None
            }
        }
    }

    /// The hostnames a more specific plain HTTP listener of a Gateway the
    /// route binds takes from it, with the own port of their listeners
    /// (`None`: the main HTTP port): a listener on the same port, which the
    /// route is not attached to, whose hostname one the route binds there
    /// covers. A request for such a host belongs to that listener alone.
    /// Likewise between the `HTTPS` listeners on a port of their own.
    fn isolated_hostnames(&self, route: &HTTPRoute) -> Vec<IsolatedHost> {
        let mut isolated = self.isolated_hostnames_of(route, false);
        isolated.extend(self.isolated_hostnames_of(route, true));
        isolated
    }

    /// [`Self::isolated_hostnames`] between the plain HTTP listeners, or the
    /// `HTTPS` ones on a port of their own when `secure`.
    fn isolated_hostnames_of(&self, route: &HTTPRoute, secure: bool) -> Vec<IsolatedHost> {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let Some(refs) = route.spec.parent_refs.as_ref() else {
            return Vec::new();
        };
        let accepted: Vec<&HTTPRouteParentRefs> = refs
            .iter()
            .filter(|p| self.accepts_parent_ref(route_ns, *p))
            .collect();
        let g = match self.state.read() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return Vec::new();
            }
        };
        let kind = |l: &ListenerInfo| {
            if secure {
                Self::listener_serves_https(l) && g.served.own_https_port(l.port).is_some()
            } else {
                Self::listener_is_plain_http(l)
            }
        };
        // The listeners the route binds, by Gateway.
        let mut bound: HashMap<(String, String), Vec<ListenerInfo>> = HashMap::new();
        for p in accepted {
            let ns = p.namespace.as_deref().unwrap_or(route_ns).to_string();
            let Some(listeners) = g.gateways.get(&(ns.clone(), p.name.clone())) else {
                continue;
            };
            bound
                .entry((ns.clone(), p.name.clone()))
                .or_default()
                .extend(
                    listeners
                        .iter()
                        .filter(|l| kind(l))
                        .filter(|l| l.admits(&ns, route_ns, "HTTPRoute", &g.namespace_labels))
                        .filter(|l| {
                            p.section_name.as_deref().is_none_or(|s| s == l.name)
                                && p.port.is_none_or(|port| port == l.port)
                        })
                        .cloned(),
                );
        }
        // Whether `taken`, a listener's hostname on `port`, is taken from
        // the listeners the route binds on that Gateway (`attached`).
        let takes = |listeners: &[ListenerInfo],
                     attached: &[ListenerInfo],
                     port: i32,
                     taken: &str| {
            let unbound = listeners.iter().any(|l| {
                kind(l)
                    && l.port == port
                    && l.hostname.as_deref() == Some(taken)
                    && !attached.iter().any(|a| a.name == l.name)
            });
            unbound
                && attached.iter().any(|l| {
                    l.port == port
                        && match l.hostname.as_deref() {
                            None => true,
                            Some(broader) => broader != taken && hostname_covers(broader, taken),
                        }
                })
        };
        let mut isolated: Vec<IsolatedHost> = Vec::new();
        for (key, attached) in &bound {
            let Some(listeners) = g.gateways.get(key) else {
                continue;
            };
            for other in listeners.iter().filter(|l| kind(l)) {
                let Some(taken) = other.hostname.as_deref() else {
                    continue;
                };
                if !takes(listeners, attached, other.port, taken) {
                    continue;
                }
                // Another Gateway the route binds on the same port, whose
                // listener for the host is one the route binds, keeps it.
                let elsewhere = bound.iter().any(|(k, a)| {
                    k != key
                        && g.gateways
                            .get(k)
                            .is_some_and(|ls| Self::selects(ls, a, other.port, taken, &kind))
                });
                if elsewhere {
                    continue;
                }
                let port = if secure {
                    g.served.own_https_port(other.port)
                } else {
                    g.served.own_http_port(other.port)
                };
                // A listener the route binds within this one takes its
                // hosts back.
                let bound_within: Vec<String> = bound
                    .values()
                    .flatten()
                    .filter(|l| l.port == other.port)
                    .filter_map(|l| l.hostname.clone())
                    .filter(|narrower| narrower != taken && hostname_covers(taken, narrower))
                    .collect();
                if !isolated.iter().any(|i| i.port == port && i.host == taken) {
                    isolated.push(IsolatedHost {
                        secure,
                        port,
                        host: taken.to_string(),
                        bound_within,
                    });
                }
            }
        }
        isolated
    }

    /// Whether the most specific listener of `listeners` `kind` takes, on
    /// `port`, covering `host` is one of `attached`.
    fn selects(
        listeners: &[ListenerInfo],
        attached: &[ListenerInfo],
        port: i32,
        host: &str,
        kind: &dyn Fn(&ListenerInfo) -> bool,
    ) -> bool {
        let specificity = |l: &ListenerInfo| match l.hostname.as_deref() {
            None => (0, 0),
            Some(h) if h.starts_with("*.") => (1, h.len()),
            Some(h) => (2, h.len()),
        };
        let covering: Vec<&ListenerInfo> = listeners
            .iter()
            .filter(|l| kind(l) && l.port == port)
            .filter(|l| {
                l.hostname
                    .as_deref()
                    .is_none_or(|h| hostname_covers(h, host))
            })
            .collect();
        let Some(best) = covering.iter().map(|l| specificity(l)).max() else {
            return false;
        };
        covering
            .iter()
            .filter(|l| specificity(l) == best)
            .any(|l| attached.iter().any(|a| a.name == l.name))
    }

    /// The own ports of the plain HTTP listeners the route binds.
    fn own_http_ports(&self, route: &HTTPRoute) -> BTreeSet<u16> {
        self.bound_listeners(route, &Self::listener_is_plain_http)
            .into_iter()
            .flatten()
            .filter_map(|l| self.own_http_port(&l))
            .collect()
    }

    /// The own ports of the `HTTPS` listeners the route binds.
    fn own_https_ports(&self, route: &HTTPRoute) -> BTreeSet<u16> {
        self.bound_listeners(route, &Self::listener_serves_https)
            .into_iter()
            .flatten()
            .filter_map(|l| self.own_https_port(&l))
            .collect()
    }

    /// The port to redirect plain HTTP requests to, for a route only served
    /// over HTTPS on the main HTTPS port: the port of the `HTTPS` listeners
    /// served there it binds, when they all share one other than 443. `None`
    /// keeps the default port.
    fn https_redirect_port(&self, route: &HTTPRoute) -> Option<u16> {
        let route_hostnames = route.spec.hostnames.clone().unwrap_or_default();
        let ports: HashSet<i32> = self
            .bound_listeners(route, &|l| {
                Self::listener_serves_https(l) && self.own_https_port(l).is_none()
            })
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

    /// Whether a listener the route binds admits one of its hostnames, an
    /// `HTTPS` listener counting whether it has a certificate or not.
    fn listener_hostname_matches(&self, route: &HTTPRoute) -> bool {
        let route_hostnames = route.spec.hostnames.clone().unwrap_or_default();
        self.bound_listeners_where(route, &Self::listener_serves_http, false)
            .iter()
            .any(|selected| intersect_hostnames(&route_hostnames, selected).is_some())
    }

    /// The listeners each accepted `parentRef` of the route binds among those
    /// `listener_ok` takes, one list per parentRef that binds any.
    fn bound_listeners(
        &self,
        route: &HTTPRoute,
        listener_ok: &dyn Fn(&ListenerInfo) -> bool,
    ) -> Vec<Vec<ListenerInfo>> {
        self.bound_listeners_where(route, listener_ok, true)
    }

    /// [`Self::bound_listeners`], an `HTTPS` listener without a usable
    /// certificate left out only when `need_certificate`.
    fn bound_listeners_where(
        &self,
        route: &HTTPRoute,
        listener_ok: &dyn Fn(&ListenerInfo) -> bool,
        need_certificate: bool,
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
                    !need_certificate
                        || !Self::listener_serves_https(l)
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
            // Only that class's Gateways: those of another class stay
            // accepted, and nothing would bring them back otherwise.
            let gone: Vec<(String, String)> = g
                .gateway_objects
                .iter()
                .filter(|(_, gw)| gw.spec.gateway_class_name == name)
                .map(|(key, _)| key.clone())
                .collect();
            for key in gone {
                g.gateways.remove(&key);
                g.gateway_objects.remove(&key);
            }
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
    pub fn allows_backend_ref(&self, from_ns: &str, to_ns: &str, service: &str) -> bool {
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
                .iter()
                .any(|((ns, _), grant)| ns == to_ns && grant.allows(from_ns, service)),
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

    /// Record Sōzune's addresses, and rewrite the status of every Gateway it
    /// owns when they change. Waits for room in the status channel rather
    /// than drop a write: no other event would bring the address up to date.
    pub async fn set_addresses(&self, addresses: Vec<(String, String)>) {
        let (writes, status_tx) = {
            let mut g = match self.state.write() {
                Ok(g) => g,
                Err(e) => {
                    error!("Gateway API: scope lock poisoned: {}", e);
                    return;
                }
            };
            if g.addresses.as_ref() == Some(&addresses) {
                return;
            }
            g.addresses = Some(addresses);
            let writes: Vec<StatusWrite> = g
                .gateway_objects
                .iter()
                .filter(|(key, _)| g.gateways.contains_key(*key))
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

    /// Write the status of Gateway `ns/name` again after a while, as it is
    /// then: a status write that failed is not tried again otherwise until
    /// something else changes.
    fn retry_gateway_status(&self, ns: &str, name: &str) {
        let scope = self.clone();
        let key = (ns.to_string(), name.to_string());
        tokio::spawn(async move {
            tokio::time::sleep(STATUS_RETRY_DELAY).await;
            let (gateway, status_tx) = match scope.state.read() {
                Ok(g) if g.gateways.contains_key(&key) => {
                    (g.gateway_objects.get(&key).cloned(), g.status_tx.clone())
                }
                _ => return,
            };
            if let (Some(gateway), Some(status_tx)) = (gateway, status_tx) {
                let _ = status_tx
                    .send(StatusWrite::Gateway(Box::new(gateway)))
                    .await;
            }
        });
    }

    /// Queue the status write of the GatewayClass `name` again after
    /// [`STATUS_RETRY_DELAY`], from the class as it is then, unless Sōzune no
    /// longer owns it.
    fn retry_gatewayclass_status(&self, client: Client, name: String) {
        let scope = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(STATUS_RETRY_DELAY).await;
            let status_tx = match scope.state.read() {
                Ok(g) if g.gateway_classes.contains(&name) => g.status_tx.clone(),
                _ => return,
            };
            let Some(status_tx) = status_tx else {
                return;
            };
            let api: Api<GatewayClass> = Api::all(client.clone());
            match bounded_status_write(api.get(&name)).await {
                // Handed to another controller meanwhile: not ours to write.
                Ok(class) if class.spec.controller_name != SOZUNE_CONTROLLER_NAME => {}
                Ok(class) => {
                    let _ = status_tx
                        .send(StatusWrite::GatewayClass(Box::new(class)))
                        .await;
                }
                Err(kube::Error::Api(r)) if r.code == 404 => {}
                Err(e) => {
                    warn!(
                        "Gateway API: failed to read GatewayClass {}, trying again shortly: {}",
                        name, e
                    );
                    scope.retry_gatewayclass_status(client, name);
                }
            }
        });
    }

    #[cfg(test)]
    pub(crate) fn published_addresses_for_tests(&self) -> Option<Vec<(String, String)>> {
        self.state.read().ok()?.addresses.clone()
    }

    /// The `status.addresses` of the Gateways Sōzune owns, `None` when it
    /// publishes none.
    fn gateway_addresses(&self) -> Option<Vec<GatewayStatusAddresses>> {
        let g = self.state.read().ok()?;
        g.addresses.as_ref().map(|addresses| {
            addresses
                .iter()
                .map(|(type_, value)| GatewayStatusAddresses {
                    r#type: Some(type_.clone()),
                    value: value.clone(),
                })
                .collect()
        })
    }

    /// Record the labels of a namespace; `None` once it is gone.
    pub fn set_namespace_labels(&self, name: &str, labels: Option<BTreeMap<String, String>>) {
        self.update_namespace_labels(|known| match labels {
            Some(labels) => known.insert(name.to_string(), labels.clone()) != Some(labels),
            None => known.remove(name).is_some(),
        });
    }

    /// Replace every namespace's labels with those a relist brought, at
    /// once: one re-resolution for the whole list.
    pub fn replace_namespace_labels(&self, labels: HashMap<String, BTreeMap<String, String>>) {
        self.update_namespace_labels(|known| {
            let changed = *known != labels;
            *known = labels;
            changed
        });
    }

    /// Apply `update` to the namespace labels. When it changed them, the
    /// routes are resolved again and the Gateways with a listener admitting
    /// namespaces by selector get their status rewritten.
    fn update_namespace_labels(
        &self,
        update: impl FnOnce(&mut HashMap<String, BTreeMap<String, String>>) -> bool,
    ) {
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return;
            }
        };
        if !update(&mut g.namespace_labels) {
            return;
        }
        let selecting: Vec<Gateway> = g
            .gateway_objects
            .iter()
            .filter(|(key, _)| {
                g.gateways.get(*key).is_some_and(|listeners| {
                    listeners
                        .iter()
                        .any(|l| matches!(l.allowed_namespaces, AllowedNamespaces::Selector(_)))
                })
            })
            .map(|(_, gateway)| gateway.clone())
            .collect();
        for gateway in selecting {
            queue_status_write(
                g.status_tx.as_ref(),
                StatusWrite::Gateway(Box::new(gateway)),
            );
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
        let grants: HashMap<(String, String), ServiceGrant> = kept
            .iter()
            .filter_map(|grant| {
                Some((
                    (
                        grant.metadata.namespace.clone()?,
                        grant.metadata.name.clone()?,
                    ),
                    ServiceGrant::of(grant)?,
                ))
            })
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
        let changed = g.reference_grants != grants || g.secret_grants.len() != before;
        g.reference_grants = grants;
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
        let (Some(ns), Some(name)) = (
            grant.metadata.namespace.as_deref(),
            grant.metadata.name.as_deref(),
        ) else {
            return false;
        };
        self.update_secret_grant(grant, SecretGrant::of(grant));
        let key = (ns.to_string(), name.to_string());
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return false;
            }
        };
        let changed = match ServiceGrant::of(grant) {
            Some(service_grant) => {
                g.reference_grants.insert(key, service_grant.clone()) != Some(service_grant)
            }
            None => g.reference_grants.remove(&key).is_some(),
        };
        drop(g);
        self.fire_if(changed)
    }

    /// Mutates the scope on a ReferenceGrant delete: drop what it authorised.
    pub fn remove_reference_grant(&self, grant: &ReferenceGrant) -> bool {
        let (Some(ns), Some(name)) = (
            grant.metadata.namespace.as_deref(),
            grant.metadata.name.as_deref(),
        ) else {
            return false;
        };
        self.update_secret_grant(grant, None);
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(e) => {
                error!("Gateway API: scope lock poisoned: {}", e);
                return false;
            }
        };
        let changed = g
            .reference_grants
            .remove(&(ns.to_string(), name.to_string()))
            .is_some();
        drop(g);
        self.fire_if(changed)
    }
}

/// What a ReferenceGrant lets routes reference among the Services of its
/// namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ServiceGrant {
    /// The namespaces of the routes it trusts.
    from: HashSet<String>,
    /// The Services it opens, `None` for all of them.
    names: Option<HashSet<String>>,
}

impl ServiceGrant {
    /// `None` when the grant opens no Service to any route.
    fn of(grant: &ReferenceGrant) -> Option<Self> {
        let from = trusted_route_from_namespaces(grant);
        let mut names = Some(HashSet::new());
        for to in grant
            .spec
            .to
            .iter()
            .filter(|t| t.group.is_empty() && t.kind == "Service")
        {
            match (&to.name, names.as_mut()) {
                (Some(name), Some(names)) => {
                    names.insert(name.clone());
                }
                (None, _) => names = None,
                (Some(_), None) => {}
            }
        }
        let opens_any = names.as_ref().is_none_or(|n| !n.is_empty());
        (!from.is_empty() && opens_any).then_some(Self { from, names })
    }

    fn allows(&self, from_ns: &str, service: &str) -> bool {
        self.from.contains(from_ns) && self.names.as_ref().is_none_or(|n| n.contains(service))
    }
}

/// Decides whether a cross-namespace backendRef is authorised. Abstracted
/// behind a trait so `route_to_entrypoints` stays testable without a live
/// [`GatewayScope`]: production passes the scope (grant-aware), tests can
/// pass a stub.
pub trait BackendRefAuthorizer {
    /// True iff a route in `from_ns` may reference Service `service` in
    /// `to_ns`.
    fn allows(&self, from_ns: &str, to_ns: &str, service: &str) -> bool;
}

impl BackendRefAuthorizer for GatewayScope {
    fn allows(&self, from_ns: &str, to_ns: &str, service: &str) -> bool {
        self.allows_backend_ref(from_ns, to_ns, service)
    }
}

/// A [`BackendRefAuthorizer`] that permits every cross-namespace reference.
/// Same-namespace refs never consult an authorizer, so this only matters
/// for the cross-namespace paths in tests that predate grant enforcement.
#[cfg(test)]
pub struct AllowAllBackendRefs;

#[cfg(test)]
impl BackendRefAuthorizer for AllowAllBackendRefs {
    fn allows(&self, _from_ns: &str, _to_ns: &str, _service: &str) -> bool {
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
                    AllowedNamespaces::Selector(
                        l.allowed_routes
                            .as_ref()
                            .and_then(|a| a.namespaces.as_ref())
                            .and_then(|n| n.selector.as_ref())
                            .and_then(NamespaceSelector::of),
                    )
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
    let (status_tx, status_rx) =
        mpsc::channel::<(HTTPRoute, RouteOutcome, Option<InvalidRef>)>(256);
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

/// Whether a watch failed because the API server refuses the request.
fn is_forbidden(error: &watcher::Error) -> bool {
    let code = match error {
        watcher::Error::InitialListFailed(kube::Error::Api(r))
        | watcher::Error::WatchStartFailed(kube::Error::Api(r))
        | watcher::Error::WatchFailed(kube::Error::Api(r)) => r.code,
        watcher::Error::WatchError(r) => r.code,
        _ => return false,
    };
    code == 401 || code == 403
}

/// Watch the namespaces' labels, which `allowedRoutes.namespaces.selector`
/// matches routes' namespaces against.
pub async fn run_namespace_watcher(client: Client, scope: GatewayScope) {
    use k8s_openapi::api::core::v1::Namespace;
    use kube::runtime::WatchStreamExt;

    let mut failing = false;
    // A new watch on every refusal: one resumed from where it stopped would
    // not list again the namespaces whose labels were dropped.
    loop {
        let api: Api<Namespace> = Api::all(client.clone());
        let mut stream = watcher::watcher(api, watcher::Config::default())
            .default_backoff()
            .boxed();
        // The namespaces a relist brings back, applied together once it is
        // done: those it does not bring back are gone.
        let mut relisted: HashMap<String, BTreeMap<String, String>> = HashMap::new();
        while let Some(event) = stream.next().await {
            match event {
                Ok(Event::InitApply(ns)) => {
                    if let Some(name) = ns.metadata.name.clone() {
                        relisted.insert(name, ns.metadata.labels.unwrap_or_default());
                    }
                }
                Ok(Event::Apply(ns)) => {
                    if let Some(name) = ns.metadata.name.clone() {
                        scope.set_namespace_labels(
                            &name,
                            Some(ns.metadata.labels.unwrap_or_default()),
                        );
                    }
                }
                Ok(Event::Delete(ns)) => {
                    if let Some(name) = ns.metadata.name.as_deref() {
                        scope.set_namespace_labels(name, None);
                    }
                }
                Ok(Event::Init) => relisted.clear(),
                Ok(Event::InitDone) => {
                    failing = false;
                    scope.replace_namespace_labels(std::mem::take(&mut relisted));
                }
                Err(e) => {
                    if !failing {
                        failing = true;
                        warn!(
                            "Gateway API: cannot watch namespaces; without the RBAC to, listeners admitting routes by namespace selector admit none: {}",
                            e
                        );
                    } else {
                        debug!("Gateway API: Namespace watcher error: {}", e);
                    }
                    // Permission lost: the labels can no longer be kept up
                    // to date, so they stop admitting routes until a new
                    // watch lists them again. Another failure is a passing
                    // one, as for every watcher: the labels stay.
                    if is_forbidden(&e) {
                        scope.replace_namespace_labels(HashMap::new());
                        break;
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
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
    mut rx: mpsc::Receiver<(HTTPRoute, RouteOutcome, Option<InvalidRef>)>,
    scope: GatewayScope,
) {
    info!("Gateway API: HTTPRoute status writer started");
    while let Some((route, outcome, invalid_ref)) = rx.recv().await {
        let Some(name) = route.metadata.name.as_deref() else {
            continue;
        };
        let ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let our_status = build_route_status(&route, &scope, outcome, invalid_ref);
        let (_, changed) = merge_route_status(route.status.as_ref(), our_status.clone());
        if !changed {
            continue;
        }
        let api: Api<HTTPRoute> = Api::namespaced(client.clone(), ns);
        let parents = |r: &HTTPRoute| {
            r.status
                .as_ref()
                .map(|s| s.parents.clone())
                .unwrap_or_default()
        };
        match bounded_status_write(patch_route_parents(&api, name, our_status, parents)).await {
            Ok(true) => debug!(
                "Gateway API: status patched on HTTPRoute {}/{} (outcome={:?})",
                ns, name, outcome
            ),
            Ok(false) => {}
            Err(e) => warn!(
                "Gateway API: failed to patch status on HTTPRoute {}/{}: {}",
                ns, name, e
            ),
        }
    }
    info!("Gateway API: HTTPRoute status writer stopped");
}

/// Write `ours` into the `status.parents[]` of the route `name`, merged into
/// the entries it holds now: another controller's stay. The patch carries the
/// `resourceVersion` it was merged against, so one written in between makes
/// it fail, and it is merged again. Returns whether it wrote anything.
async fn patch_route_parents<K, T>(
    api: &Api<K>,
    name: &str,
    ours: Vec<T>,
    parents: impl Fn(&K) -> Vec<T>,
) -> Result<bool, kube::Error>
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
    T: ParentStatus + serde::Serialize,
{
    const ATTEMPTS: usize = 3;
    for attempt in 1..=ATTEMPTS {
        let current = api.get(name).await?;
        let (merged, changed) = merge_parent_status(&parents(&current), ours.clone());
        if !changed {
            return Ok(false);
        }
        // Kubernetes does not merge arrays: the patch replaces `parents`
        // whole, which `merged` keeps every other controller's entries in.
        let patch = serde_json::json!({
            "metadata": { "resourceVersion": current.meta().resource_version },
            "status": { "parents": merged }
        });
        match api
            .patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
        {
            Ok(_) => return Ok(true),
            Err(kube::Error::Api(resp)) if resp.code == 409 && attempt < ATTEMPTS => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

/// A TLSRoute, TCPRoute or UDPRoute: a route of whole connections, whose
/// status reports its parents and its backendRefs as an HTTPRoute's does.
trait L4Route:
    kube::Resource<DynamicType = (), Scope = k8s_openapi::NamespaceResourceScope>
    + Clone
    + std::fmt::Debug
    + serde::de::DeserializeOwned
    + Send
    + Sync
    + 'static
{
    const KIND: &'static str;
    /// The protocol of its backends' endpoints.
    const PROTOCOL: &'static str;
    type Parent: ParentStatus + serde::Serialize + Send + Sync;
    /// Each rule's backendRefs.
    fn backend_refs(&self) -> Vec<Vec<L4BackendRef<'_>>>;
    /// Its `status.parents[]`.
    fn status_parents(&self) -> Vec<Self::Parent>;
    /// The entries of `status.parents[]` sōzune owns, for `outcome`.
    fn build_status(
        &self,
        scope: &GatewayScope,
        outcome: RouteOutcome,
        invalid_ref: Option<InvalidRef>,
    ) -> Vec<Self::Parent>;
}

/// A backendRef of an [`L4Route`] rule, as its status reads it.
struct L4BackendRef<'a> {
    parts: BackendRefParts<'a>,
    port: Option<i32>,
    weight: Option<i32>,
}

/// [`L4Route::backend_refs`]: the rules of TLS, TCP and UDP routes share
/// their shape, not their type.
macro_rules! l4_backend_refs {
    ($route:expr) => {
        $route
            .spec
            .rules
            .iter()
            .map(|rule| {
                rule.backend_refs
                    .iter()
                    .flatten()
                    .map(|b| L4BackendRef {
                        parts: BackendRefParts {
                            group: b.group.as_deref(),
                            kind: b.kind.as_deref(),
                            namespace: b.namespace.as_deref(),
                            name: &b.name,
                        },
                        port: b.port,
                        weight: b.weight,
                    })
                    .collect()
            })
            .collect()
    };
}

/// An entry of [`L4Route::build_status`], from a parentRef `$p` and its
/// conditions: the status types of TLS, TCP and UDP routes share their shape.
macro_rules! l4_parent_status {
    ($parent:ident, $parent_ref:ident, $p:expr, $conditions:expr) => {
        $parent {
            controller_name: SOZUNE_CONTROLLER_NAME.to_string(),
            parent_ref: $parent_ref {
                group: $p.group.clone(),
                kind: $p.kind.clone(),
                name: $p.name.clone(),
                namespace: $p.namespace.clone(),
                port: $p.port,
                section_name: $p.section_name.clone(),
            },
            conditions: Some($conditions),
        }
    };
}

impl L4Route for TLSRoute {
    const KIND: &'static str = "TLSRoute";
    const PROTOCOL: &'static str = "TCP";
    type Parent = TLSRouteStatusParents;

    fn backend_refs(&self) -> Vec<Vec<L4BackendRef<'_>>> {
        l4_backend_refs!(self)
    }

    fn status_parents(&self) -> Vec<Self::Parent> {
        self.status
            .as_ref()
            .map(|s| s.parents.clone())
            .unwrap_or_default()
    }

    fn build_status(
        &self,
        scope: &GatewayScope,
        outcome: RouteOutcome,
        invalid_ref: Option<InvalidRef>,
    ) -> Vec<Self::Parent> {
        let route_ns = self.metadata.namespace.as_deref().unwrap_or("default");
        parent_conditions(
            scope,
            route_ns,
            self.metadata.generation,
            self.spec.parent_refs.as_deref().unwrap_or_default(),
            Self::KIND,
            &|p| scope.accepts_tls_parent_ref(route_ns, p),
            GatewayScope::listener_serves_tls_passthrough,
            // Each parent by the listeners it selects: one admitting none of
            // the route's names refuses it, whatever another does.
            &|p| {
                if outcome != RouteOutcome::NotMine
                    && scope.tls_parent_hostnames_by_port(self, p).is_empty()
                {
                    RouteOutcome::NoMatchingListenerHostname
                } else {
                    outcome
                }
            },
            invalid_ref,
        )
        .into_iter()
        .map(|(p, conditions)| {
            l4_parent_status!(
                TLSRouteStatusParents,
                TLSRouteStatusParentsParentRef,
                p,
                conditions
            )
        })
        .collect()
    }
}

impl L4Route for TCPRoute {
    const KIND: &'static str = "TCPRoute";
    const PROTOCOL: &'static str = "TCP";
    type Parent = TCPRouteStatusParents;

    fn backend_refs(&self) -> Vec<Vec<L4BackendRef<'_>>> {
        l4_backend_refs!(self)
    }

    fn status_parents(&self) -> Vec<Self::Parent> {
        self.status
            .as_ref()
            .map(|s| s.parents.clone())
            .unwrap_or_default()
    }

    fn build_status(
        &self,
        scope: &GatewayScope,
        outcome: RouteOutcome,
        invalid_ref: Option<InvalidRef>,
    ) -> Vec<Self::Parent> {
        let route_ns = self.metadata.namespace.as_deref().unwrap_or("default");
        parent_conditions(
            scope,
            route_ns,
            self.metadata.generation,
            self.spec.parent_refs.as_deref().unwrap_or_default(),
            Self::KIND,
            &|p| scope.accepts_tcp_parent_ref(route_ns, p),
            GatewayScope::listener_serves_tcp,
            &|_| outcome,
            invalid_ref,
        )
        .into_iter()
        .map(|(p, conditions)| {
            l4_parent_status!(
                TCPRouteStatusParents,
                TCPRouteStatusParentsParentRef,
                p,
                conditions
            )
        })
        .collect()
    }
}

impl L4Route for UDPRoute {
    const KIND: &'static str = "UDPRoute";
    const PROTOCOL: &'static str = "UDP";
    type Parent = UDPRouteStatusParents;

    fn backend_refs(&self) -> Vec<Vec<L4BackendRef<'_>>> {
        l4_backend_refs!(self)
    }

    fn status_parents(&self) -> Vec<Self::Parent> {
        self.status
            .as_ref()
            .map(|s| s.parents.clone())
            .unwrap_or_default()
    }

    fn build_status(
        &self,
        scope: &GatewayScope,
        outcome: RouteOutcome,
        invalid_ref: Option<InvalidRef>,
    ) -> Vec<Self::Parent> {
        let route_ns = self.metadata.namespace.as_deref().unwrap_or("default");
        parent_conditions(
            scope,
            route_ns,
            self.metadata.generation,
            self.spec.parent_refs.as_deref().unwrap_or_default(),
            Self::KIND,
            &|p| scope.accepts_udp_parent_ref(route_ns, p),
            GatewayScope::listener_serves_udp,
            &|_| outcome,
            invalid_ref,
        )
        .into_iter()
        .map(|(p, conditions)| {
            l4_parent_status!(
                UDPRouteStatusParents,
                UDPRouteStatusParentsParentRef,
                p,
                conditions
            )
        })
        .collect()
    }
}

/// What an [`L4Route`] watcher hands its status writer.
type L4StatusTx<R> = mpsc::Sender<(R, RouteOutcome, Option<InvalidRef>)>;

/// Start the status writer of an [`L4Route`] kind, as
/// [`run_httproute_watcher`] does for HTTPRoutes.
fn spawn_l4_status_writer<R: L4Route>(client: Client, scope: GatewayScope) -> L4StatusTx<R> {
    let (tx, rx) = mpsc::channel(256);
    tokio::spawn(run_l4_status_writer::<R>(client, rx, scope));
    tx
}

/// The [`L4Route`] twin of [`run_status_writer`].
async fn run_l4_status_writer<R: L4Route>(
    client: Client,
    mut rx: mpsc::Receiver<(R, RouteOutcome, Option<InvalidRef>)>,
    scope: GatewayScope,
) {
    info!("Gateway API: {} status writer started", R::KIND);
    while let Some((route, outcome, invalid_ref)) = rx.recv().await {
        let Some(name) = route.meta().name.clone() else {
            continue;
        };
        let ns = route
            .meta()
            .namespace
            .clone()
            .unwrap_or_else(|| "default".to_string());
        let ours = route.build_status(&scope, outcome, invalid_ref);
        let (_, changed) = merge_parent_status(&route.status_parents(), ours.clone());
        if !changed {
            continue;
        }
        let api: Api<R> = Api::namespaced(client.clone(), &ns);
        match bounded_status_write(patch_route_parents(&api, &name, ours, R::status_parents)).await
        {
            Ok(true) => debug!(
                "Gateway API: status patched on {} {}/{} (outcome={:?})",
                R::KIND,
                ns,
                name,
                outcome
            ),
            Ok(false) => {}
            Err(e) => warn!(
                "Gateway API: failed to patch status on {} {}/{}: {}",
                R::KIND,
                ns,
                name,
                e
            ),
        }
    }
    info!("Gateway API: {} status writer stopped", R::KIND);
}

/// Hand an [`L4Route`]'s `outcome` to its status writer, with the first of
/// its backendRefs that cannot be used. Best effort, as for HTTPRoutes.
fn report_l4_status<R: L4Route>(
    route: &R,
    outcome: RouteOutcome,
    resolver: &dyn ServiceResolver,
    scope: &GatewayScope,
    status_tx: Option<&L4StatusTx<R>>,
) {
    let invalid_ref = l4_route_invalid_ref(route, resolver, scope);
    if let Some(tx) = status_tx
        && let Err(e) = tx.try_send((route.clone(), outcome, invalid_ref))
    {
        debug!(
            "Gateway API: {} status channel full or closed: {}",
            R::KIND,
            e
        );
    }
}

/// The outcome of an [`L4Route`] whose acceptance takes no hostnames:
/// whether a parent of ours takes it (`accepted`), then its backends.
fn l4_outcome<R: L4Route>(
    route: &R,
    accepted: bool,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
) -> RouteOutcome {
    if !accepted {
        RouteOutcome::NotMine
    } else if l4_route_backends_ready(route, resolver, grants) {
        RouteOutcome::Accepted
    } else {
        RouteOutcome::NoResolvableBackends
    }
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

/// Marks a Gateway some of whose `listeners` are not accepted: its
/// `Accepted` condition says `ListenersNotValid`, still `True` while another
/// listener is accepted. With none left, it is neither accepted nor
/// programmed.
fn mark_invalid_listeners(
    conditions: &mut [Condition],
    listeners: &[gateway_api::apis::standard::gateways::GatewayStatusListeners],
) {
    let invalid = listeners
        .iter()
        .filter(|l| {
            l.conditions
                .iter()
                .any(|c| c.type_ == CONDITION_TYPE_ACCEPTED && c.status == "False")
        })
        .count();
    if invalid == 0 {
        return;
    }
    let none_valid = invalid == listeners.len();
    for condition in conditions.iter_mut() {
        if condition.type_ == CONDITION_TYPE_ACCEPTED {
            condition.reason = REASON_LISTENERS_NOT_VALID.to_string();
            condition.message = format!(
                "{invalid} of the Gateway's {} listeners are not valid",
                listeners.len()
            );
        } else if condition.type_ == CONDITION_TYPE_PROGRAMMED && none_valid {
            condition.reason = REASON_INVALID.to_string();
            condition.message = "No listener of the Gateway is valid".to_string();
        } else {
            continue;
        }
        if none_valid {
            condition.status = "False".to_string();
        }
    }
}

const REASON_LISTENERS_NOT_VALID: &str = "ListenersNotValid";
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
        // An HTTP listener on a port of `gateway_ports.http` is served there,
        // once opened. Any other is served on Sōzune's HTTP port, which a
        // Service commonly maps the listener's port to: served whatever its
        // port, its status says where.
        "HTTP" => (Some("HTTPRoute"), served.http_problem(listener.port)),
        // Likewise on Sōzune's HTTPS port or one of `gateway_ports.https`,
        // when the listener terminates TLS.
        "HTTPS" if GatewayScope::listener_serves_https(listener) => {
            (Some("HTTPRoute"), served.https_problem(listener.port))
        }
        // A TLS listener carries TLSRoutes in Passthrough mode only.
        "TLS" if !GatewayScope::listener_serves_tls_passthrough(listener) => (None, None),
        // On the HTTPS port, by its passthrough listener when it has one.
        "TLS" if served.https_passthrough && port == Some(served.https) => (Some("TLSRoute"), None),
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
                "HTTP" => served.own_http_port(listener.port).unwrap_or(served.http),
                "HTTPS" => served.own_https_port(listener.port).unwrap_or(served.https),
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
            StatusWrite::GatewayClass(class) => {
                patch_gatewayclass_status(&client, &scope, &class).await
            }
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
    let listener_statuses = scope.listener_statuses(gateway);
    let mut ours = build_gateway_conditions(gateway, true);
    mark_invalid_listeners(&mut ours, &listener_statuses);
    let existing = gateway
        .status
        .as_ref()
        .and_then(|s| s.conditions.as_deref());
    let (merged, conditions_changed) = merge_conditions(existing, ours);
    let (listeners, listeners_changed) = merge_listener_statuses(
        gateway.status.as_ref().and_then(|s| s.listeners.as_deref()),
        listener_statuses,
    );
    // Written only when Sōzune publishes an address: otherwise what is
    // there is left alone.
    let addresses = scope.gateway_addresses();
    let addresses_changed = addresses.as_ref().is_some_and(|ours| {
        gateway
            .status
            .as_ref()
            .and_then(|s| s.addresses.as_ref())
            .is_none_or(|current| current != ours)
    });
    if !conditions_changed && !listeners_changed && !addresses_changed {
        return;
    }
    let mut patch = serde_json::json!({
        "status": { "conditions": merged, "listeners": listeners }
    });
    if let Some(addresses) = addresses {
        patch["status"]["addresses"] = serde_json::json!(addresses);
    }
    let api: Api<Gateway> = Api::namespaced(client.clone(), ns);
    let pp = PatchParams::default();
    match bounded_status_write(api.patch_status(name, &pp, &Patch::Merge(&patch))).await {
        // Deleted meanwhile: nothing left to write.
        Err(kube::Error::Api(r)) if r.code == 404 => {
            debug!(
                "Gateway API: Gateway {}/{} is gone, its status is not written",
                ns, name
            );
        }
        Err(e) => {
            warn!(
                "Gateway API: failed to patch status on Gateway {}/{}, trying again shortly: {}",
                ns, name, e
            );
            scope.retry_gateway_status(ns, name);
        }
        Ok(_) => {
            debug!("Gateway API: status patched on Gateway {}/{}", ns, name);
        }
    }
}

/// Patch the `Accepted` condition onto a GatewayClass's status. A class
/// reaches the writer only when sōzune owns it (controllerName matches); a
/// class pointing at another controller is never queued, as Gateway API
/// requires.
async fn patch_gatewayclass_status(client: &Client, scope: &GatewayScope, class: &GatewayClass) {
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
    match bounded_status_write(api.patch_status(name, &pp, &Patch::Merge(&patch))).await {
        // Deleted meanwhile: nothing left to write.
        Err(kube::Error::Api(r)) if r.code == 404 => {}
        Err(e) => {
            warn!(
                "Gateway API: failed to patch status on GatewayClass {}, trying again shortly: {}",
                name, e
            );
            scope.retry_gatewayclass_status(client.clone(), name.to_string());
        }
        Ok(_) => debug!("Gateway API: status patched on GatewayClass {}", name),
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
    status_tx: Option<&mpsc::Sender<(HTTPRoute, RouteOutcome, Option<InvalidRef>)>>,
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
    // Routes that declare unsupported filters (extensionRef) or the
    // conflicting requestRedirect+urlRewrite pair are also dropped: routing
    // them as if the filter wasn't there would silently rewrite user intent.
    // Worse than refusing the route — better to surface the problem so the
    // user knows to fall back to Ingress annotations until filter support
    // lands. (requestRedirect, requestHeaderModifier, responseHeaderModifier,
    // urlRewrite and requestMirror are honoured.)
    let (outcome, new_entrypoints) = if !scope.accepts_route(route) {
        (RouteOutcome::NotMine, Vec::new())
    } else if route_has_unsupported_filters(route, resolver, scope) {
        let ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let name = route.metadata.name.as_deref().unwrap_or("<no-name>");
        warn!(
            "Gateway API: HTTPRoute {}/{} declares filters sōzune cannot represent (requestRedirect, requestHeaderModifier, responseHeaderModifier, urlRewrite and requestMirror are supported; extensionRef is not, and requestRedirect cannot be combined with urlRewrite on the same rule) — dropping the route",
            ns, name
        );
        (RouteOutcome::UnsupportedFilters, Vec::new())
    } else if route_has_unsupported_matches(route) {
        let ns = route.metadata.namespace.as_deref().unwrap_or("default");
        let name = route.metadata.name.as_deref().unwrap_or("<no-name>");
        warn!(
            "Gateway API: HTTPRoute {}/{} declares a RegularExpression path match, or a header or query one that does not compile — dropping the route",
            ns, name
        );
        (RouteOutcome::UnsupportedMatches, Vec::new())
    } else {
        // Narrow the route's hostnames by the listener(s) it binds to, over
        // HTTP and over HTTPS: a listener with a `hostname` only serves
        // matching route hostnames. `None` means no bound listener of that
        // kind admits any of the route's hostnames.
        // A plain HTTP listener on a port of its own serves the route there;
        // the others, on the main HTTP port.
        let plain = scope.effective_hostnames_for_route(route, &|l| {
            GatewayScope::listener_is_plain_http(l) && scope.own_http_port(l).is_none()
        });
        let secure = scope.effective_hostnames_for_route(route, &|l| {
            GatewayScope::listener_serves_https(l) && scope.own_https_port(l).is_none()
        });
        // Likewise an HTTPS listener: on its port, over HTTPS alone.
        let own_secure_ports: Vec<(u16, Vec<String>)> = scope
            .own_https_ports(route)
            .into_iter()
            .filter_map(|port| {
                let hostnames = scope.effective_hostnames_for_route(route, &|l| {
                    GatewayScope::listener_serves_https(l) && scope.own_https_port(l) == Some(port)
                })?;
                Some((port, hostnames))
            })
            .collect();
        let own_ports: Vec<(u16, Vec<String>)> = scope
            .own_http_ports(route)
            .into_iter()
            .filter_map(|port| {
                let hostnames = scope.effective_hostnames_for_route(route, &|l| {
                    GatewayScope::listener_is_plain_http(l) && scope.own_http_port(l) == Some(port)
                })?;
                Some((port, hostnames))
            })
            .collect();
        if plain.is_none()
            && secure.is_none()
            && own_ports.is_empty()
            && own_secure_ports.is_empty()
        {
            // A hostname may match an HTTPS listener that has no usable
            // certificate yet: its own status says so.
            let outcome = if scope.listener_hostname_matches(route) {
                RouteOutcome::NoResolvableBackends
            } else {
                RouteOutcome::NoMatchingListenerHostname
            };
            (outcome, Vec::new())
        } else {
            // The names served over plain HTTP on a listener of its own port,
            // every host when one admits any.
            let plain_elsewhere: Option<Vec<String>> = if own_ports.is_empty() {
                None
            } else if own_ports.iter().any(|(_, names)| names.is_empty()) {
                Some(Vec::new())
            } else {
                Some(
                    own_ports
                        .iter()
                        .flat_map(|(_, names)| names.clone())
                        .collect(),
                )
            };
            let mut eps = if plain.is_none() && secure.is_none() {
                Vec::new()
            } else {
                route_entrypoints_by_scheme(
                    route,
                    resolver,
                    scope,
                    plain,
                    secure,
                    scope.https_redirect_port(route),
                    plain_elsewhere.as_deref(),
                )
            };
            for (port, hostnames) in own_ports {
                eps.extend(own_port_entrypoints(
                    route, resolver, scope, port, hostnames, false,
                ));
            }
            for (port, hostnames) in own_secure_ports {
                eps.extend(own_port_entrypoints(
                    route, resolver, scope, port, hostnames, true,
                ));
            }
            let isolated = scope.isolated_hostnames(route);
            // Every host taken by more specific listeners still leaves the
            // route accepted, its backends resolved.
            let resolved = !eps.is_empty();
            let skips_conditions = eps.iter().any(redirect_skips_conditions);
            let eps = isolate_from_listeners(eps, &isolated);
            if skips_conditions {
                warn!(
                    "Gateway API: HTTPRoute {}/{} redirects on a match whose query or header conditions Sōzu cannot route on (a prefix redirect with query matches, a header match on Host or Cookie…) — dropping the route",
                    route.metadata.namespace.as_deref().unwrap_or("default"),
                    route.metadata.name.as_deref().unwrap_or("<no-name>")
                );
                (RouteOutcome::UnsupportedFilters, Vec::new())
            } else {
                // A mirror with no ready pod copies nothing: its backendRef is
                // no more resolved than a backend's would be.
                let mirror_unready = eps
                    .iter()
                    .any(|ep| ep.config.mirrors.iter().any(|m| m.backends.is_empty()));
                let outcome = if !resolved || mirror_unready {
                    RouteOutcome::NoResolvableBackends
                } else {
                    RouteOutcome::Accepted
                };
                (outcome, eps)
            }
        }
    };

    // Best-effort status notification. We send the route (cloned —
    // tiny payload relative to the network round-trip) to the status
    // writer; it computes the desired status, deduplicates against the
    // current object, and PATCHes only when something changed. Send
    // failures are non-fatal: status is observability, not routing.
    let invalid_ref = route_invalid_ref(route, resolver, scope);
    if let Some(tx) = status_tx
        && let Err(e) = tx.try_send((route.clone(), outcome, invalid_ref))
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
    status_tx: Option<&mpsc::Sender<(HTTPRoute, RouteOutcome, Option<InvalidRef>)>>,
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
    /// Each ready pod's address and the port it listens on.
    pods: Vec<(String, u16)>,
    /// The header edits of the backendRef's own filters.
    headers: Vec<HeaderConfig>,
}

/// How a rule's requests split between its pods and errors, from the weights
/// of its backendRefs: forwarded, invalid (`500`) and without a ready pod
/// (`503`). `None` when no share is answered with an error.
fn failing_shares(shares: [u128; 3]) -> Option<crate::model::FailingShares> {
    if shares[1..].iter().all(|&w| w == 0) {
        return None;
    }
    let divisor = shares.iter().copied().fold(0, gcd);
    let mut shares = shares.map(|w| w / divisor);
    let largest = shares.iter().copied().max().unwrap_or(1);
    if largest > MAX_POD_WEIGHT {
        // Scaled down, a share keeping at least 1.
        shares = shares.map(|w| {
            if w == 0 {
                0
            } else {
                (w * MAX_POD_WEIGHT / largest).max(1)
            }
        });
    }
    Some(crate::model::FailingShares {
        forwarded: shares[0] as u32,
        invalid: shares[1] as u32,
        unavailable: shares[2] as u32,
    })
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
                let headers = r.headers;
                r.pods.into_iter().map(move |(address, port)| Backend {
                    address,
                    port,
                    weight: weight as u32,
                    headers: headers.clone(),
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

    /// The ready pods behind the `protocol` port `port` of `service`, each
    /// with the port it listens on: the Service's `targetPort`. The Service
    /// port itself when that is not known.
    fn pod_addresses(
        &self,
        namespace: &str,
        service: &str,
        port: u16,
        _protocol: &str,
    ) -> Vec<(String, u16)> {
        self.pod_ips(namespace, service)
            .into_iter()
            .map(|ip| (ip, port))
            .collect()
    }

    /// Whether `service` exists, `None` when that is not known yet.
    fn service_exists(&self, _namespace: &str, _service: &str) -> Option<bool> {
        None
    }
}

impl ServiceResolver for crate::provider::kubernetes::KubernetesProvider {
    fn pod_ips(&self, namespace: &str, service: &str) -> Vec<String> {
        self.pod_ips_for(&format!("{namespace}/{service}"))
    }

    fn pod_addresses(
        &self,
        namespace: &str,
        service: &str,
        port: u16,
        protocol: &str,
    ) -> Vec<(String, u16)> {
        self.pod_addresses_for(&format!("{namespace}/{service}"), port, protocol)
    }

    fn service_exists(&self, namespace: &str, service: &str) -> Option<bool> {
        crate::provider::kubernetes::KubernetesProvider::service_exists(
            self,
            &format!("{namespace}/{service}"),
        )
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
    plain_elsewhere: Option<&[String]>,
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

    // A name served over plain HTTP on a listener of its own port gets
    // nothing on the main HTTP port, not even a redirect (`plain_elsewhere`:
    // every host when empty).
    let elsewhere = |name: &str| {
        plain_elsewhere.is_some_and(|names| {
            // Either way round: a wildcard over such a name takes it too.
            names.is_empty() || names.iter().any(|other| hostnames_compatible(other, name))
        })
    };
    let (secure_alone, secure_only): (Vec<String>, Vec<String>) =
        secure_only.into_iter().partition(|h| elsewhere(h));
    // (hostnames, served over HTTPS, plain HTTP redirected, id suffix); one
    // served over HTTPS without being redirected is served over HTTPS alone.
    let mut sets: Vec<(Vec<String>, bool, bool, &str)> = [
        (plain_only, false, false, ""),
        (both, true, false, "-tls"),
        (secure_only, true, true, "-https"),
        (secure_alone, true, false, "-https-only"),
    ]
    .into_iter()
    .filter(|(hostnames, ..)| !hostnames.is_empty())
    .collect();
    // A scheme admitting every host serves the route on any host (`*`),
    // tried after every route naming its hosts.
    let any = || vec!["*".to_string()];
    match (plain_all, secure_all) {
        (true, true) => sets.push((any(), true, false, "-tls")),
        (true, false) => sets.push((any(), false, false, "")),
        // A redirect on any host would take those served elsewhere too.
        (false, true) if plain_elsewhere.is_some() => {
            sets.push((any(), true, false, "-https-only"))
        }
        (false, true) => sets.push((any(), true, true, "-https")),
        (false, false) => {}
    }
    if sets.is_empty() {
        sets.push(if only_secure {
            (any(), true, true, "-https")
        } else {
            (any(), false, false, "")
        });
    }

    let mut entrypoints = Vec::new();
    for (hostnames, tls, redirect, suffix) in sets {
        // Sōzune orders a route by its most specific hostname: a route's
        // wildcard must not be tried as early as its exact names, so each
        // goes into an entrypoint of its own.
        let groups = specificity_groups(hostnames);
        let numbered = groups.len() > 1;
        for (group, hostnames) in groups.into_iter().enumerate() {
            let suffix = if numbered {
                format!("{suffix}-h{group}")
            } else {
                suffix.to_string()
            };
            // A Gateway API wildcard takes any number of labels.
            let hostnames: Vec<String> = hostnames
                .iter()
                .map(|h| crate::model::any_labels_wildcard(h))
                .collect();
            for mut ep in route_to_entrypoints_with_hostnames(route, resolver, grants, &hostnames) {
                ep.id.push_str(&suffix);
                ep.name.push_str(&suffix);
                ep.config.tls = tls;
                ep.config.https_only = suffix.starts_with("-https-only");
                ep.config.https_redirect = redirect;
                if redirect {
                    ep.config.https_redirect_port = https_port;
                }
                entrypoints.push(ep);
            }
        }
    }
    entrypoints
}

/// The entrypoints of a route on the plain HTTP listeners it binds on `port`,
/// a port of their own: served on that port's listener, plain HTTP only. With
/// `secure`, on the `HTTPS` listeners it binds there, HTTPS only.
fn own_port_entrypoints(
    route: &HTTPRoute,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
    port: u16,
    hostnames: Vec<String>,
    secure: bool,
) -> Vec<Entrypoint> {
    let mut eps = if secure {
        // Every host served elsewhere over plain HTTP: no redirect from it.
        route_entrypoints_by_scheme(
            route,
            resolver,
            grants,
            None,
            Some(hostnames),
            None,
            Some(&[]),
        )
    } else {
        route_entrypoints_by_scheme(route, resolver, grants, Some(hostnames), None, None, None)
    };
    for ep in &mut eps {
        let (suffix, listener) = if secure {
            (
                format!("-sp{port}"),
                crate::config::gateway_https_listener(port),
            )
        } else {
            (
                format!("-p{port}"),
                crate::config::gateway_http_listener(port),
            )
        };
        ep.id.push_str(&suffix);
        ep.name.push_str(&suffix);
        ep.config.entrypoint = Some(listener);
        // A redirect keeping the scheme and naming no port keeps the
        // listener's: Gateway API sends the client back to the port it came
        // on.
        if ep.config.redirect.is_some()
            && ep.config.redirect_scheme.is_none()
            && ep.config.rewrite_port.is_none()
        {
            ep.config.rewrite_port = Some(port);
        }
    }
    eps
}

/// A host a listener the route is not attached to takes from it, on `port`
/// (`None`: the main HTTP port), save within `bound_within`: the hostnames
/// of the listeners the route binds within that one. Between `HTTPS`
/// listeners on a port of their own when `secure`.
#[derive(Debug, Clone, PartialEq)]
struct IsolatedHost {
    secure: bool,
    port: Option<u16>,
    host: String,
    bound_within: Vec<String>,
}

/// `eps` kept from the hosts more specific listeners take (`isolated`, see
/// [`GatewayScope::isolated_hostnames`]): a hostname wholly within one is
/// dropped, an entrypoint left with none with it; over a broader one, an
/// entrypoint answering `404` on that host and the entrypoint's path is added,
/// tried after every route of that host.
fn isolate_from_listeners(eps: Vec<Entrypoint>, isolated: &[IsolatedHost]) -> Vec<Entrypoint> {
    if isolated.is_empty() {
        return eps;
    }
    let mut out = Vec::new();
    for mut ep in eps {
        // On an `HTTPS` listener of its own port, or an HTTP one.
        let listener = ep.config.entrypoint.as_deref();
        let (secure, port) = match listener.and_then(crate::config::gateway_https_port) {
            Some(port) => (true, Some(port)),
            None => (false, listener.and_then(crate::config::gateway_http_port)),
        };
        let on_port: Vec<&IsolatedHost> = isolated
            .iter()
            .filter(|i| i.secure == secure && i.port == port)
            .collect();
        let taken: Vec<&str> = on_port.iter().map(|i| i.host.as_str()).collect();
        if taken.is_empty() || (!secure && ep.config.https_only) {
            out.push(ep);
            continue;
        }
        // Isolation is a matter of the HTTP listener: served over HTTPS
        // too, a hostname taken there stays, over HTTPS alone. On an
        // `HTTPS` listener of its own port, of that listener.
        let (within, kept): (Vec<String>, Vec<String>) = std::mem::take(&mut ep.config.hostnames)
            .into_iter()
            .partition(|h| {
                on_port.iter().any(|i| {
                    host_within(h, &i.host) && !i.bound_within.iter().any(|b| host_within(h, b))
                })
            });
        if !secure && ep.config.tls && !within.is_empty() {
            let mut over_https = ep.clone();
            over_https.id = format!("{}-sec", ep.id);
            over_https.name = format!("{}-sec", ep.name);
            over_https.source = Some(over_https.id.clone());
            over_https.config.hostnames = within;
            over_https.config.https_only = true;
            over_https.config.https_redirect = false;
            over_https.config.https_redirect_port = None;
            out.push(over_https);
        }
        ep.config.hostnames = kept;
        if ep.config.hostnames.is_empty() {
            continue;
        }
        let shadows = other_listener_entrypoints(&ep, &taken, secure);
        // The hosts of the listeners it binds within a taken one, ahead of
        // that one's shadow.
        let mut reclaimed: Vec<String> = Vec::new();
        for i in on_port
            .iter()
            .filter(|i| ep.config.hostnames.iter().any(|h| serves_host(h, &i.host)))
        {
            for host in i
                .bound_within
                .iter()
                .map(|b| crate::model::any_labels_wildcard(b))
            {
                if !ep.config.hostnames.contains(&host) && !reclaimed.contains(&host) {
                    reclaimed.push(host);
                }
            }
        }
        if !reclaimed.is_empty() {
            let mut bound = ep.clone();
            bound.id = format!("{}-bound", ep.id);
            bound.name = format!("{}-bound", ep.name);
            bound.source = Some(bound.id.clone());
            bound.config.hostnames = reclaimed;
            out.push(bound);
        }
        out.push(ep);
        out.extend(shadows);
    }
    out
}

/// Whether an entrypoint hostname (`*`, an any-labels wildcard, or a name)
/// only takes hosts within `taken`, a Gateway API hostname.
fn host_within(entrypoint_host: &str, taken: &str) -> bool {
    if entrypoint_host == "*" {
        return false;
    }
    // The hosts it takes end with `.base`, or are `base` itself.
    let (base, wildcard) = match entrypoint_host.strip_prefix(crate::model::ANY_LABELS_PREFIX) {
        Some(suffix) => (suffix, true),
        None => (entrypoint_host, false),
    };
    match taken.strip_prefix("*.") {
        Some(suffix) => base.ends_with(&format!(".{suffix}")) || (wildcard && base == suffix),
        None => !wildcard && base == taken,
    }
}

/// The entrypoints answering `404` on the hosts of `taken` `ep` is broader
/// than, on `ep`'s path, tried after every route of those hosts: on its
/// `HTTPS` listener when `secure`, its HTTP one otherwise.
fn other_listener_entrypoints(ep: &Entrypoint, taken: &[&str], secure: bool) -> Vec<Entrypoint> {
    taken
        .iter()
        .filter(|host| ep.config.hostnames.iter().any(|h| serves_host(h, host)))
        .enumerate()
        .map(|(i, host)| {
            let mut shadow = ep.clone();
            shadow.id = format!("{}-iso{i}", ep.id);
            shadow.name = format!("{}-iso{i}", ep.name);
            shadow.source = Some(shadow.id.clone());
            shadow.backends = Vec::new();
            let config = &mut shadow.config;
            config.hostnames = vec![crate::model::any_labels_wildcard(host)];
            config.answer = Some(crate::model::FixedAnswer::OtherListener);
            // The route's matches, so its frontends take no precedence
            // over the shadow (a header predicate is tried first): whatever
            // else the route asks, the request is not its listener's.
            config.tls = secure;
            config.https_only = secure;
            config.https_redirect = false;
            config.https_redirect_port = None;
            config.redirect = None;
            config.redirect_scheme = None;
            config.redirect_template = None;
            config.rewrite_host = None;
            config.rewrite_path = None;
            config.rewrite_port = None;
            config.rewrite = None;
            config.headers = Vec::new();
            config.backend_timeout = None;
            config.request_timeout = None;
            shadow
        })
        .collect()
}

/// Whether an entrypoint hostname (`*`, an any-labels wildcard, or a name)
/// takes `host`, a Gateway API hostname, a wildcard or not.
fn serves_host(entrypoint_host: &str, host: &str) -> bool {
    if entrypoint_host == "*" || entrypoint_host == host {
        return true;
    }
    match entrypoint_host.strip_prefix(crate::model::ANY_LABELS_PREFIX) {
        Some(suffix) => host
            .strip_prefix("*.")
            .unwrap_or(host)
            .ends_with(&format!(".{suffix}")),
        None => false,
    }
}

/// Hostnames split by how specific they are: the exact names together, then
/// each wildcard on its own, `*` last.
fn specificity_groups(hostnames: Vec<String>) -> Vec<Vec<String>> {
    let (exact, wildcards): (Vec<String>, Vec<String>) =
        hostnames.into_iter().partition(|h| !h.starts_with('*'));
    let mut groups = Vec::new();
    if !exact.is_empty() {
        groups.push(exact);
    }
    groups.extend(wildcards.into_iter().map(|w| vec![w]));
    if groups.is_empty() {
        groups.push(Vec::new());
    }
    groups
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
/// A rule with no backendRef, or none it can use, answers 500; a redirect
/// rule needs none.
///
/// Other silent skips:
/// - rules with backends that resolve to zero pod IPs
/// - matches that aren't `Path` (header/query/method-only matches)
/// - a `RegularExpression` path match (the route is rejected upstream)
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
/// can't faithfully execute today (`extensionRef`, a `requestRedirect` in
/// an unmappable form, an empty `urlRewrite`, an entry doing more than one
/// thing, or the conflicting `requestRedirect`+`urlRewrite` pair on one
/// rule). `requestRedirect`, `requestHeaderModifier`,
/// `responseHeaderModifier`, `urlRewrite` and `requestMirror` are
/// supported. The HTTPRoute watcher uses
/// this as an early reject so the user sees a clear log line and a
/// `ResolvedRefs=False` status condition rather than wrong behaviour.
pub fn route_has_unsupported_filters(
    route: &HTTPRoute,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
) -> bool {
    let namespace = route.metadata.namespace.as_deref().unwrap_or("default");
    let usable = |b: &HTTPRouteRulesBackendRefs| backend_ref_usable(namespace, b, resolver, grants);
    route
        .spec
        .rules
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(
            |rule| match gateway_filters::effective_rule_filters(rule, &usable) {
                Some(filters) => {
                    (!filters.is_empty() && !gateway_filters::rule_filters_supported(&filters))
                        || replaces_prefix_off_a_prefix_match(rule, &filters)
                }
                None => true,
            },
        )
}

/// Whether a rule replaces the matched prefix (a `replacePrefixMatch` in a
/// `requestRedirect` or `urlRewrite`) on a match that is not a path prefix:
/// Gateway API allows it with a `PathPrefix` match only.
fn replaces_prefix_off_a_prefix_match(
    rule: &HTTPRouteRules,
    filters: &[gateway_api::apis::standard::httproutes::HTTPRouteRulesFilters],
) -> bool {
    let replaces_prefix = filters.iter().any(|f| {
        f.request_redirect
            .as_ref()
            .and_then(|r| r.path.as_ref())
            .is_some_and(|p| p.replace_prefix_match.is_some())
            || f.url_rewrite
                .as_ref()
                .and_then(|r| r.path.as_ref())
                .is_some_and(|p| p.replace_prefix_match.is_some())
    });
    replaces_prefix
        && rule.matches.iter().flatten().any(|m| {
            m.path
                .as_ref()
                .and_then(|p| p.r#type.as_ref())
                .is_some_and(|t| *t != HTTPRouteRulesMatchesPathType::PathPrefix)
        })
}

/// Whether `ep` redirects on conditions only the middleware checks: Sōzu
/// answers a redirect itself, before the middleware could refuse the request.
fn redirect_skips_conditions(ep: &Entrypoint) -> bool {
    ep.answers_without_backend()
        && (crate::middleware::middleware_query_conditions(&ep.config).is_some()
            || !crate::middleware::middleware_header_conditions(&ep.config).is_empty())
}

/// True iff any match in the route declares a condition sōzune can't
/// represent — a `type: RegularExpression` path match, or a header or query
/// one that does not compile. Treated like an unsupported filter: the route is
/// rejected (logged, and reflected as `ResolvedRefs=False
/// reason=UnsupportedValue`) rather than served with the condition dropped,
/// which would route more traffic than the author asked for.
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
const REASON_NO_MATCHING_LISTENER_HOSTNAME: &str = "NoMatchingListenerHostname";
const REASON_INVALID_KIND: &str = "InvalidKind";

/// Why a backendRef cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidRef {
    /// Not a Service: the only kind Sōzune routes to.
    Kind,
    /// A Service of another namespace no ReferenceGrant lets the route use.
    NotPermitted,
    /// A Service that does not exist.
    NotFound,
}

impl InvalidRef {
    /// The `ResolvedRefs` reason and message it reports.
    fn condition(self) -> (&'static str, &'static str) {
        match self {
            Self::Kind => (REASON_INVALID_KIND, "A backendRef is not a Service"),
            Self::NotPermitted => (
                REASON_REF_NOT_PERMITTED,
                "A backendRef names a Service of another namespace no ReferenceGrant allows",
            ),
            Self::NotFound => (
                REASON_BACKEND_NOT_FOUND,
                "A backendRef names a Service that does not exist",
            ),
        }
    }
}

/// Why `backend` cannot be used by a route of `namespace`, if it cannot.
fn check_backend_ref(
    namespace: &str,
    backend: &HTTPRouteRulesBackendRefs,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
) -> Result<(), InvalidRef> {
    check_backend_ref_parts(
        namespace,
        BackendRefParts {
            group: backend.group.as_deref(),
            kind: backend.kind.as_deref(),
            namespace: backend.namespace.as_deref(),
            name: &backend.name,
        },
        resolver,
        grants,
    )
}

/// What [`check_backend_ref_parts`] looks at in a backendRef, whatever the
/// route's kind.
#[derive(Clone, Copy)]
struct BackendRefParts<'a> {
    group: Option<&'a str>,
    kind: Option<&'a str>,
    namespace: Option<&'a str>,
    name: &'a str,
}

/// [`check_backend_ref`] for a backendRef of any route kind.
fn check_backend_ref_parts(
    namespace: &str,
    backend: BackendRefParts<'_>,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
) -> Result<(), InvalidRef> {
    // Service-typed backends only. group/kind defaulting to empty/Service
    // per Gateway API spec is what we accept.
    let kind_ok = backend.kind.is_none_or(|k| k == "Service");
    let group_ok = backend.group.is_none_or(str::is_empty);
    if !kind_ok || !group_ok {
        return Err(InvalidRef::Kind);
    }
    let target_ns = backend.namespace.unwrap_or(namespace);
    // Cross-namespace backendRefs require a ReferenceGrant in the target
    // namespace trusting this route's namespace: a namespace must opt in to
    // being referenced. Same-namespace refs never consult the grant set.
    if !grants.allows(namespace, target_ns, backend.name) {
        return Err(InvalidRef::NotPermitted);
    }
    if resolver.service_exists(target_ns, backend.name) == Some(false) {
        return Err(InvalidRef::NotFound);
    }
    Ok(())
}

/// Whether every rule of an [`L4Route`] has a backendRef taking traffic, and
/// every backendRef that can be used and takes traffic has a ready endpoint.
fn l4_route_backends_ready<R: L4Route>(
    route: &R,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
) -> bool {
    let namespace = route.meta().namespace.as_deref().unwrap_or("default");
    route.backend_refs().into_iter().all(|refs| {
        let usable: Vec<L4BackendRef<'_>> = refs
            .into_iter()
            .filter(|b| b.weight != Some(0))
            .filter(|b| check_backend_ref_parts(namespace, b.parts, resolver, grants).is_ok())
            .collect();
        // A rule left with none forwards nothing.
        !usable.is_empty()
            && usable.iter().all(|b| {
                let target_ns = b.parts.namespace.unwrap_or(namespace);
                b.port
                    .and_then(|p| u16::try_from(p).ok())
                    .is_some_and(|port| {
                        !resolver
                            .pod_addresses(target_ns, b.parts.name, port, R::PROTOCOL)
                            .is_empty()
                    })
            })
    })
}

/// The first backendRef of an [`L4Route`] that cannot be used, if any.
fn l4_route_invalid_ref<R: L4Route>(
    route: &R,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
) -> Option<InvalidRef> {
    let namespace = route.meta().namespace.as_deref().unwrap_or("default");
    route
        .backend_refs()
        .into_iter()
        .flatten()
        .find_map(|b| check_backend_ref_parts(namespace, b.parts, resolver, grants).err())
}

/// Whether `backend` can take traffic: weighted, usable, with a ready pod.
fn backend_ref_usable(
    namespace: &str,
    backend: &HTTPRouteRulesBackendRefs,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
) -> bool {
    let Some(port) = backend.port.and_then(|p| u16::try_from(p).ok()) else {
        return false;
    };
    let target_ns = backend.namespace.as_deref().unwrap_or(namespace);
    backend.weight != Some(0)
        && check_backend_ref(namespace, backend, resolver, grants).is_ok()
        && !resolver
            .pod_addresses(target_ns, &backend.name, port, "TCP")
            .is_empty()
}

/// Where the `requestMirror` filters of a rule copy its requests: each
/// mirror's Service resolved to its ready pods. One that cannot be used, or
/// has no ready pod, is kept without backends and copies nothing: the rule
/// is served all the same, and its frontend does not move as the mirror's
/// pods come and go.
fn rule_mirrors(
    namespace: &str,
    route_name: &str,
    rule_index: usize,
    filters: &[HTTPRouteRulesFilters],
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
) -> Vec<Mirror> {
    gateway_filters::mirror_backend_refs(filters)
        .into_iter()
        .map(|m| {
            let parts = BackendRefParts {
                group: m.group.as_deref(),
                kind: m.kind.as_deref(),
                namespace: m.namespace.as_deref(),
                name: &m.name,
            };
            if let Err(reason) = check_backend_ref_parts(namespace, parts, resolver, grants) {
                warn!(
                    "Gateway API: HTTPRoute {}/{} rule {} cannot mirror to {} ({:?})",
                    namespace, route_name, rule_index, m.name, reason
                );
                return Mirror {
                    backends: Vec::new(),
                };
            }
            let target_ns = m.namespace.as_deref().unwrap_or(namespace);
            let backends = m
                .port
                .and_then(|p| u16::try_from(p).ok())
                .and_then(|port| {
                    weigh_backend_refs(vec![ResolvedRef {
                        weight: None,
                        pods: resolver.pod_addresses(target_ns, &m.name, port, "TCP"),
                        headers: Vec::new(),
                    }])
                })
                .unwrap_or_default();
            Mirror { backends }
        })
        .collect()
}

/// The first backendRef of `route` that cannot be used, if any.
fn route_invalid_ref(
    route: &HTTPRoute,
    resolver: &dyn ServiceResolver,
    grants: &dyn BackendRefAuthorizer,
) -> Option<InvalidRef> {
    let namespace = route.metadata.namespace.as_deref().unwrap_or("default");
    let rules = || route.spec.rules.iter().flatten();
    let backends = rules()
        .flat_map(|rule| rule.backend_refs.iter().flatten())
        .find_map(|b| check_backend_ref(namespace, b, resolver, grants).err());
    // The Services the rules mirror to are backendRefs too.
    backends.or_else(|| {
        rules()
            .flat_map(|rule| rule.filters.iter().flatten())
            .filter_map(|f| f.request_mirror.as_ref())
            .find_map(|m| {
                let parts = BackendRefParts {
                    group: m.backend_ref.group.as_deref(),
                    kind: m.backend_ref.kind.as_deref(),
                    namespace: m.backend_ref.namespace.as_deref(),
                    name: &m.backend_ref.name,
                };
                check_backend_ref_parts(namespace, parts, resolver, grants).err()
            })
    })
}

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
    /// A match sōzune cannot represent (a `RegularExpression` path, or a
    /// header or query regex that does not compile) dropped the route.
    /// Reflected as `Accepted=False reason=UnsupportedValue`; its
    /// backendRefs are reported on as usual.
    UnsupportedMatches,
    /// In scope, no filters, but every backendRef resolved to zero
    /// ready endpoints. Surfaces as `ResolvedRefs=False
    /// reason=BackendNotFound` so users can distinguish "I'm waiting
    /// on pods" from "my route is wrong".
    NoResolvableBackends,
    /// No listener the route binds to admits any of its hostnames.
    /// Surfaces as `Accepted=False reason=NoMatchingListenerHostname`.
    NoMatchingListenerHostname,
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
/// [`GatewayScope::parent_refusal`]). `Accepted=True` iff the outcome is
/// [`RouteOutcome::Accepted`] or [`RouteOutcome::NoResolvableBackends`].
/// `ResolvedRefs` speaks of the route's backendRefs, whether the parent
/// accepts the route or not: `False` for unsupported filters, a backendRef
/// that cannot be used (`invalid_ref`), or no ready endpoint.
fn build_route_status(
    route: &HTTPRoute,
    scope: &GatewayScope,
    outcome: RouteOutcome,
    invalid_ref: Option<InvalidRef>,
) -> Vec<HTTPRouteStatusParents> {
    let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
    parent_conditions(
        scope,
        route_ns,
        route.metadata.generation,
        route.spec.parent_refs.as_deref().unwrap_or_default(),
        "HTTPRoute",
        &|p| scope.accepts_parent_ref(route_ns, p),
        GatewayScope::listener_serves_http,
        &|_| outcome,
        invalid_ref,
    )
    .into_iter()
    .map(|(p, conditions)| HTTPRouteStatusParents {
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
    .collect()
}

/// The conditions sōzune reports on each parentRef of a route of
/// `route_kind` (see [`build_route_status`]): `Accepted` and `ResolvedRefs`
/// for one the route is `accepted` on, and for one a Gateway of ours refuses,
/// through no listener `listener_ok` takes. A parent that is not ours gets
/// none.
#[allow(clippy::too_many_arguments)]
fn parent_conditions<'a, P: ParentRef>(
    scope: &GatewayScope,
    route_ns: &str,
    generation: Option<i64>,
    parent_refs: &'a [P],
    route_kind: &str,
    accepted: &dyn Fn(&P) -> bool,
    listener_ok: fn(&ListenerInfo) -> bool,
    outcome: &dyn Fn(&P) -> RouteOutcome,
    invalid_ref: Option<InvalidRef>,
) -> Vec<(&'a P, Vec<Condition>)> {
    let now = Time(k8s_openapi::chrono::Utc::now());
    let condition = |type_: &str, status: &str, reason: &str, message: String| Condition {
        type_: type_.to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message,
        last_transition_time: now.clone(),
        observed_generation: generation,
    };

    parent_refs
        .iter()
        .filter_map(|p| {
            let (
                (accepted_status, accepted_reason, accepted_msg),
                (refs_status, refs_reason, refs_msg),
            ) = outcome_verdicts(outcome(p), invalid_ref);
            let resolved_refs = || {
                condition(
                    CONDITION_TYPE_RESOLVED_REFS,
                    refs_status,
                    refs_reason,
                    refs_msg.clone(),
                )
            };
            let conditions = if accepted(p) {
                vec![
                    condition(
                        CONDITION_TYPE_ACCEPTED,
                        accepted_status,
                        accepted_reason,
                        accepted_msg.clone(),
                    ),
                    resolved_refs(),
                ]
            } else {
                // Reported rather than skipped: silence would read as a
                // Gateway that ignores the route. A parent that is not ours
                // gets no entry.
                let reason = scope.parent_refusal(route_ns, p, route_kind, listener_ok)?;
                let message = if reason == REASON_NO_MATCHING_PARENT {
                    "No listener of this Gateway matches the parentRef's sectionName and port"
                        .to_string()
                } else {
                    format!(
                        "No listener selected by this parentRef allows {}s from namespace {}",
                        route_kind, route_ns
                    )
                };
                vec![
                    condition(CONDITION_TYPE_ACCEPTED, "False", reason, message),
                    resolved_refs(),
                ]
            };
            Some((p, conditions))
        })
        .collect()
}

/// What `Accepted` and `ResolvedRefs` say, as (status, reason, message), of
/// a route `outcome` describes on a parent.
type Verdict = (&'static str, &'static str, String);

fn outcome_verdicts(outcome: RouteOutcome, invalid_ref: Option<InvalidRef>) -> (Verdict, Verdict) {
    let accepted = match outcome {
        RouteOutcome::Accepted | RouteOutcome::NoResolvableBackends => (
            "True",
            REASON_ACCEPTED,
            "Route accepted by sōzune".to_string(),
        ),
        RouteOutcome::UnsupportedFilters => (
            "False",
            REASON_UNSUPPORTED_VALUE,
            "Route declares HTTPRoute filters sōzune cannot represent (extensionRef is unsupported, and requestRedirect cannot be combined with urlRewrite on the same rule; requestRedirect, requestHeaderModifier, responseHeaderModifier, urlRewrite and requestMirror are supported)".to_string(),
        ),
        RouteOutcome::UnsupportedMatches => (
            "False",
            REASON_UNSUPPORTED_VALUE,
            "Route declares a match sōzune cannot represent: a RegularExpression path match, or a header or query regular expression that does not compile".to_string(),
        ),
        RouteOutcome::NoMatchingListenerHostname => (
            "False",
            REASON_NO_MATCHING_LISTENER_HOSTNAME,
            "No listener of the Gateway admits any of the route's hostnames".to_string(),
        ),
        // No parentRef is accepted, so these are never used.
        RouteOutcome::NotMine => ("False", "", String::new()),
    };
    let refs = match (outcome, invalid_ref) {
        (RouteOutcome::UnsupportedFilters, _) => (
            "False",
            REASON_UNSUPPORTED_VALUE,
            "Route filters are not supported".to_string(),
        ),
        (_, Some(invalid)) => {
            let (reason, message) = invalid.condition();
            ("False", reason, message.to_string())
        }
        (RouteOutcome::NoResolvableBackends, None) => (
            "False",
            REASON_BACKEND_NOT_FOUND,
            "No ready endpoints found for one or more backendRefs".to_string(),
        ),
        _ => (
            "True",
            REASON_RESOLVED_REFS,
            "All backendRefs resolved to ready endpoints".to_string(),
        ),
    };
    (accepted, refs)
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
    merge_parent_status(
        existing.map(|s| s.parents.as_slice()).unwrap_or_default(),
        ours,
    )
}

/// An entry of a route's `status.parents[]`, whatever the route's kind.
trait ParentStatus: Clone {
    fn controller_name(&self) -> &str;
    /// Whether `other` reports the same parent, with equivalent conditions.
    fn equivalent(&self, other: &Self) -> bool;
}

macro_rules! impl_parent_status {
    ($t:ty) => {
        impl ParentStatus for $t {
            fn controller_name(&self) -> &str {
                &self.controller_name
            }
            fn equivalent(&self, other: &Self) -> bool {
                self.parent_ref == other.parent_ref
                    && conditions_equivalent(
                        self.conditions.as_deref(),
                        other.conditions.as_deref(),
                    )
            }
        }
    };
}

impl_parent_status!(HTTPRouteStatusParents);
impl_parent_status!(TLSRouteStatusParents);
impl_parent_status!(TCPRouteStatusParents);
impl_parent_status!(UDPRouteStatusParents);

/// [`merge_route_status`] for a route of any kind.
fn merge_parent_status<T: ParentStatus>(existing: &[T], ours: Vec<T>) -> (Vec<T>, bool) {
    let foreign: Vec<T> = existing
        .iter()
        .filter(|p| p.controller_name() != SOZUNE_CONTROLLER_NAME)
        .cloned()
        .collect();
    let our_existing: Vec<&T> = existing
        .iter()
        .filter(|p| p.controller_name() == SOZUNE_CONTROLLER_NAME)
        .collect();

    // Skip the write if our slice is byte-for-byte equivalent (modulo
    // last_transition_time, which we recompute every call). Comparing
    // conditions field-by-field with the timestamp ignored avoids
    // hammering the apiserver on every periodic re-resolve.
    let unchanged = our_existing.len() == ours.len()
        && our_existing
            .iter()
            .zip(ours.iter())
            .all(|(a, b)| a.equivalent(b));

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
    // native frontend path/host rewrite (transparent, no redirect), and
    // `requestMirror` → a copy the middleware sends. A rule carrying any
    // filter we can't represent (extensionRef), or the conflicting
    // requestRedirect+urlRewrite pair, is refused
    // outright: routing it as if the filter weren't there would silently
    // rewrite user intent. The watcher also gates on
    // `route_has_unsupported_filters` to set the route status, but we
    // re-check here so a direct call can't slip an unsupported filter
    // through.
    let usable = |b: &HTTPRouteRulesBackendRefs| backend_ref_usable(namespace, b, resolver, grants);
    let Some(filters) = gateway_filters::effective_rule_filters(rule, &usable) else {
        return Vec::new();
    };
    let (redirect, header_edits, url_rewrite) = if filters.is_empty() {
        (None, Vec::new(), None)
    } else {
        if !gateway_filters::rule_filters_supported(&filters) {
            return Vec::new();
        }
        (
            gateway_filters::redirect_from_filter(&filters),
            gateway_filters::header_edits_from_filters(&filters),
            gateway_filters::url_rewrite_from_filter(&filters),
        )
    };

    // A redirect answers every request itself, backend or not.
    let answers = redirect
        .as_ref()
        .is_some_and(|r| r.policy.answers_without_backend());
    let backend_refs = rule.backend_refs.as_deref().unwrap_or_default();
    // backendRefs with filters of their own: the middleware makes them. A
    // redirect forwards nothing for them to edit.
    let own_filters = !answers && !gateway_filters::backend_refs_share_filters(rule, &usable);
    let mut resolved: Vec<ResolvedRef> = Vec::new();
    let mut invalid = 0;
    // The weights of the backendRefs by what becomes of their share:
    // forwarded, answered 500, answered 503.
    let mut shares = [0u128; 3];
    let ref_weight =
        |b: &HTTPRouteRulesBackendRefs| u128::try_from(b.weight.unwrap_or(1)).unwrap_or(0);
    for b in backend_refs {
        if let Err(reason) = check_backend_ref(namespace, b, resolver, grants) {
            warn!(
                "Gateway API: HTTPRoute {}/{} rule {} cannot use backendRef {} ({:?})",
                namespace, route_name, rule_index, b.name, reason
            );
            invalid += 1;
            shares[1] += ref_weight(b);
            continue;
        }
        let Some(port) = b.port.and_then(|p| u16::try_from(p).ok()) else {
            continue;
        };
        let target_ns = b.namespace.as_deref().unwrap_or(namespace);
        let pods = resolver.pod_addresses(target_ns, &b.name, port, "TCP");
        shares[if pods.is_empty() { 2 } else { 0 }] += ref_weight(b);
        resolved.push(ResolvedRef {
            weight: b.weight,
            pods,
            headers: if own_filters {
                gateway_filters::backend_ref_header_edits(b)
            } else {
                Vec::new()
            },
        });
    }
    let failing_shares = if answers {
        None
    } else {
        failing_shares(shares)
    };
    // Gateway API: a rule with no backendRef, or none it can use, answers
    // 500.
    let invalid_backends = !answers && invalid == backend_refs.len();
    let backends = if invalid_backends {
        Vec::new()
    } else if answers {
        weigh_backend_refs(resolved).unwrap_or_default()
    } else {
        match weigh_backend_refs(resolved) {
            Some(backends) => backends,
            // No ready pod to forward to, but invalid backendRefs whose
            // share to answer. Without one, the rule waits for a pod.
            None if failing_shares.is_some_and(|s| s.invalid > 0) => Vec::new(),
            None => return Vec::new(),
        }
    };

    let (request_timeout, backend_timeout) = rule_timeouts_ms(rule);
    let mirrors = if answers {
        // A redirect forwards nothing to copy.
        Vec::new()
    } else {
        rule_mirrors(
            namespace, route_name, rule_index, &filters, resolver, grants,
        )
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
                    // Refused upstream (see `route_has_unsupported_matches`).
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
                    https_only: false,
                    redirect: redirect.as_ref().map(|r| r.policy),
                    redirect_scheme: redirect.as_ref().and_then(|r| r.scheme),
                    redirect_template: None,
                    rewrite_host: redirect.as_ref().and_then(|r| r.host.clone()),
                    rewrite_path: redirect.as_ref().and_then(|r| r.path.clone()),
                    rewrite_port: redirect.as_ref().and_then(|r| r.port),
                    rewrite: url_rewrite.clone().or_else(|| {
                        // A redirect replacing the matched prefix builds its
                        // `Location` as this rewrite does.
                        redirect
                            .as_ref()
                            .and_then(|r| r.prefix.clone())
                            .map(|prefix| UrlRewrite {
                                path: Some(PathRewrite::ReplacePrefixMatch(prefix)),
                                hostname: None,
                            })
                    }),
                    www_authenticate: None,
                    priority: 0,
                    auth: None,
                    forward_auth: None,
                    headers: header_edits.clone(),
                    backend_timeout,
                    request_timeout,
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
                    answer: invalid_backends.then_some(crate::model::FixedAnswer::InvalidBackends),
                    ip_allow_list: Vec::new(),
                    mirrors: mirrors.clone(),
                    mirror_of: None,
                    failing_shares,
                },
                source: Some(id),
                candidates: Vec::new(),
            }
        })
        .collect()
}

/// The rule's `request` and `backendRequest` timeouts in milliseconds.
/// `backendRequest: 0s` stays `Some(0)`, which disables the backend timeout;
/// `request: 0s` sets no request timeout. An invalid duration is ignored.
fn rule_timeouts_ms(rule: &HTTPRouteRules) -> (Option<u64>, Option<u64>) {
    let parse = |raw: Option<&str>| {
        let raw = raw?;
        let ms = gateway_duration_ms(raw);
        if ms.is_none() {
            warn!("Gateway API: ignoring the invalid timeout {:?}", raw);
        }
        ms
    };
    let Some(timeouts) = rule.timeouts.as_ref() else {
        return (None, None);
    };
    (
        parse(timeouts.request.as_deref()).filter(|ms| *ms > 0),
        parse(timeouts.backend_request.as_deref()),
    )
}

/// A Gateway API duration (`1h`, `30s`, `500ms`, `1m30s`) in milliseconds.
fn gateway_duration_ms(raw: &str) -> Option<u64> {
    let mut total: u64 = 0;
    let mut rest = raw;
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if digits == 0 {
            return None;
        }
        let value: u64 = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        let (unit, len) = if rest.starts_with("ms") {
            (1, 2)
        } else if rest.starts_with('h') {
            (3_600_000, 1)
        } else if rest.starts_with('m') {
            (60_000, 1)
        } else if rest.starts_with('s') {
            (1_000, 1)
        } else {
            return None;
        };
        rest = &rest[len..];
        total = total.checked_add(value.checked_mul(unit)?)?;
    }
    Some(total)
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
    status_tx: Option<&L4StatusTx<TLSRoute>>,
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
    let by_port = if scope.accepts_tls_route(route) {
        Some(scope.effective_tls_hostnames_by_port(route))
    } else {
        None
    };
    let new_entrypoints = match by_port.clone() {
        None => Vec::new(),
        // A route can bind listeners on several ports; each gets its own
        // entrypoint set, serving only the names that listener admits.
        Some(by_port) => by_port
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
            .collect(),
    };

    // A port Sōzune does not serve is the listener's to report, on its
    // status: the route stays accepted.
    let outcome = match &by_port {
        None => RouteOutcome::NotMine,
        Some(ports) if ports.is_empty() => RouteOutcome::NoMatchingListenerHostname,
        Some(_) if !l4_route_backends_ready(route, resolver, scope) => {
            RouteOutcome::NoResolvableBackends
        }
        Some(_) => RouteOutcome::Accepted,
    };
    report_l4_status(route, outcome, resolver, scope, status_tx);

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
    status_tx: Option<&L4StatusTx<TLSRoute>>,
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
        if apply_tls_route(
            route,
            storage,
            index,
            resolver,
            scope,
            listener_ports,
            status_tx,
        ) {
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
    let api: Api<TLSRoute> = Api::all(client.clone());
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

    let status_tx = spawn_l4_status_writer::<TLSRoute>(client, scope.clone());

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
                    apply_tls_route(&route, &storage, &index, resolver.as_ref(), &scope, &listener_ports, Some(&status_tx))
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
                re_resolve_all_tls(&storage, &index, resolver.as_ref(), &scope, &listener_ports, Some(&status_tx))
            }
            _ = scope.changed() => {
                debug!("Gateway API: scope changed, re-resolving TLS routes");
                re_resolve_all_tls(&storage, &index, resolver.as_ref(), &scope, &listener_ports, Some(&status_tx))
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
            if !grants.allows(namespace, target_ns, &b.name) {
                warn!(
                    "Gateway API: TCPRoute {}/{} references Service {}/{} across namespaces with no ReferenceGrant — dropping the backend",
                    namespace, route_name, target_ns, b.name
                );
                return None;
            }
            Some(ResolvedRef {
                weight: b.weight,
                pods: resolver.pod_addresses(target_ns, &b.name, port, "TCP"),
                headers: Vec::new(),
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
    status_tx: Option<&L4StatusTx<TCPRoute>>,
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

    let accepted = scope.accepts_tcp_route(route);
    // A port Sōzune does not serve is the listener's to report: the route
    // stays accepted.
    let outcome = l4_outcome(route, accepted, resolver, scope);
    report_l4_status(route, outcome, resolver, scope, status_tx);
    let new_entrypoints = if !accepted {
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
    status_tx: Option<&L4StatusTx<TCPRoute>>,
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
        if apply_tcp_route(
            route,
            storage,
            index,
            resolver,
            scope,
            listener_ports,
            status_tx,
        ) {
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
    let api: Api<TCPRoute> = Api::all(client.clone());
    if api.list(&Default::default()).await.is_err() {
        info!(
            "Gateway API: TCPRoute CRD not installed, skipping watcher (it ships in the experimental bundle)"
        );
        return Ok(());
    }
    let status_tx = spawn_l4_status_writer::<TCPRoute>(client, scope.clone());

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
                    apply_tcp_route(&route, &storage, &index, resolver.as_ref(), &scope, &listener_ports, Some(&status_tx))
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
                re_resolve_all_tcp(&storage, &index, resolver.as_ref(), &scope, &listener_ports, Some(&status_tx))
            }
            _ = scope.changed() => {
                debug!("Gateway API: scope changed, re-resolving TCP routes");
                re_resolve_all_tcp(&storage, &index, resolver.as_ref(), &scope, &listener_ports, Some(&status_tx))
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
            if !grants.allows(namespace, target_ns, &b.name) {
                warn!(
                    "Gateway API: UDPRoute {}/{} references Service {}/{} across namespaces with no ReferenceGrant — dropping the backend",
                    namespace, route_name, target_ns, b.name
                );
                return None;
            }
            Some(ResolvedRef {
                weight: b.weight,
                pods: resolver.pod_addresses(target_ns, &b.name, port, "UDP"),
                headers: Vec::new(),
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
    status_tx: Option<&L4StatusTx<UDPRoute>>,
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

    let accepted = scope.accepts_udp_route(route);
    // As for TCPRoutes.
    let outcome = l4_outcome(route, accepted, resolver, scope);
    report_l4_status(route, outcome, resolver, scope, status_tx);
    let new_entrypoints = if !accepted {
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
    status_tx: Option<&L4StatusTx<UDPRoute>>,
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
        if apply_udp_route(
            route,
            storage,
            index,
            resolver,
            scope,
            listener_ports,
            status_tx,
        ) {
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
    let api: Api<UDPRoute> = Api::all(client.clone());
    if api.list(&Default::default()).await.is_err() {
        info!(
            "Gateway API: UDPRoute CRD not installed, skipping watcher (it ships in the experimental bundle)"
        );
        return Ok(());
    }
    let status_tx = spawn_l4_status_writer::<UDPRoute>(client, scope.clone());

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
                    apply_udp_route(&route, &storage, &index, resolver.as_ref(), &scope, &listener_ports, Some(&status_tx))
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
                re_resolve_all_udp(&storage, &index, resolver.as_ref(), &scope, &listener_ports, Some(&status_tx))
            }
            _ = scope.changed() => {
                debug!("Gateway API: scope changed, re-resolving UDP routes");
                re_resolve_all_udp(&storage, &index, resolver.as_ref(), &scope, &listener_ports, Some(&status_tx))
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
#[derive(Clone)]
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

/// [`tcp_listener_ports`] for TLSRoutes: with `proxy.https.passthrough`, the
/// HTTPS port (`passthrough`) is served by its passthrough listener too.
pub fn tls_listener_ports(
    tcp: &[crate::config::TcpListenerConfig],
    gateway_ports: &crate::config::GatewayPortsConfig,
    passthrough: Option<u16>,
) -> TcpListenerPorts {
    let mut ports = ListenerPorts::clone(&tcp_listener_ports(tcp, gateway_ports));
    if let Some(port) = passthrough {
        ports.declared.insert(
            i32::from(port),
            crate::config::HTTPS_PASSTHROUGH_LISTENER.to_string(),
        );
    }
    Arc::new(ports)
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
            if !grants.allows(namespace, target_ns, &b.name) {
                warn!(
                    "Gateway API: TLSRoute {}/{} references Service {}/{} across namespaces with no ReferenceGrant — dropping the backend",
                    namespace, route_name, target_ns, b.name
                );
                return None;
            }
            Some(ResolvedRef {
                weight: b.weight,
                pods: resolver.pod_addresses(target_ns, &b.name, port, "TCP"),
                headers: Vec::new(),
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
        https_only: false,
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
        request_timeout: None,
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
        answer: None,
        mirrors: Vec::new(),
        mirror_of: None,
        failing_shares: None,
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

    /// A TLSRoute reports, on each parent of ours, `Accepted` and
    /// `ResolvedRefs`, a backendRef of another namespace no ReferenceGrant
    /// opens refusing the latter.
    #[test]
    fn a_tls_route_reports_its_status() {
        let scope = tls_scope(Some("*.example.com"), 8443);
        let route = tls_route(vec!["a.example.com"], 8443);
        let status = |route: &TLSRoute, outcome| {
            let invalid = l4_route_invalid_ref(route, &r1(), &scope);
            let parents = route.build_status(&scope, outcome, invalid);
            assert_eq!(parents.len(), 1);
            assert_eq!(parents[0].controller_name, SOZUNE_CONTROLLER_NAME);
            parents[0].conditions.clone().unwrap()
        };
        let find = |conditions: &[Condition], type_: &str| {
            let c = conditions.iter().find(|c| c.type_ == type_).unwrap();
            (c.status.clone(), c.reason.clone())
        };

        let accepted = status(&route, RouteOutcome::Accepted);
        assert_eq!(
            find(&accepted, CONDITION_TYPE_ACCEPTED),
            ("True".to_string(), REASON_ACCEPTED.to_string())
        );
        assert_eq!(
            find(&accepted, CONDITION_TYPE_RESOLVED_REFS),
            ("True".to_string(), REASON_RESOLVED_REFS.to_string())
        );

        let mut elsewhere = route.clone();
        elsewhere.spec.rules[0].backend_refs.as_mut().unwrap()[0].namespace = Some("other".into());
        let refused = status(&elsewhere, RouteOutcome::Accepted);
        assert_eq!(
            find(&refused, CONDITION_TYPE_RESOLVED_REFS),
            ("False".to_string(), REASON_REF_NOT_PERMITTED.to_string())
        );

        // A second parent whose listener admits none of its names refuses
        // it, the first still accepting it.
        let mut other = gateway("default", "gw2", "sozune");
        let mut listener = gw_listener("tls", 8443, "TLS");
        listener.hostname = Some("*.other.net".into());
        listener.tls = Some(gateway_api::apis::standard::gateways::GatewayListenersTls {
            mode: Some(GatewayListenersTlsMode::Passthrough),
            ..Default::default()
        });
        other.spec.listeners = vec![listener];
        scope.upsert_gateway(&other);
        let mut both = route.clone();
        both.spec
            .parent_refs
            .as_mut()
            .unwrap()
            .push(TLSRouteParentRefs {
                name: "gw2".into(),
                ..Default::default()
            });
        let parents = both.build_status(&scope, RouteOutcome::Accepted, None);
        let accepted: Vec<(String, String)> = parents
            .iter()
            .map(|p| find(p.conditions.as_deref().unwrap(), CONDITION_TYPE_ACCEPTED))
            .collect();
        assert_eq!(
            accepted,
            vec![
                ("True".to_string(), REASON_ACCEPTED.to_string()),
                (
                    "False".to_string(),
                    REASON_NO_MATCHING_LISTENER_HOSTNAME.to_string()
                ),
            ]
        );

        let unmatched = status(&route, RouteOutcome::NoMatchingListenerHostname);
        assert_eq!(
            find(&unmatched, CONDITION_TYPE_ACCEPTED),
            (
                "False".to_string(),
                REASON_NO_MATCHING_LISTENER_HOSTNAME.to_string()
            )
        );
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
            &ports_8443(),
            None
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

        apply_tls_route(&route, &storage, &index, &r1(), &scope, &ports_8443(), None);
        assert!(storage.read().unwrap().is_empty());
        assert_eq!(index.read().unwrap().len(), 1);

        // Declare 9443 and re-resolve: the route now lands.
        let ports = Arc::new([(9443, "tlsgw".to_string())].into_iter().collect());
        assert!(re_resolve_all_tls(
            &storage,
            &index,
            &r1(),
            &scope,
            &ports,
            None
        ));
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

        // For TLSRoutes, with passthrough on the HTTPS port.
        let ports = tls_listener_ports(&listeners, &Default::default(), Some(443));
        assert_eq!(
            ports.get(443).as_deref(),
            Some(crate::config::HTTPS_PASSTHROUGH_LISTENER)
        );
        assert_eq!(ports.get(8443).as_deref(), Some("tlsgw"));
    }

    /// A `TLS` listener on the HTTPS port is served once passthrough is on
    /// there; a `TCP` one still is not.
    #[test]
    fn a_tls_listener_on_the_https_port_is_served_by_passthrough() {
        let gw = gateway("default", "gw", "sozune");
        let tls = li_tls("tls", 443, None, GatewayListenersTlsMode::Passthrough);
        let tcp = ListenerInfo {
            protocol: "TCP".into(),
            ..li("tcp", 443, None)
        };
        let mut served = served();
        let programmed = |served: &ServedPorts, l: &ListenerInfo| {
            let status = build_listener_status(&gw, l, served, 0, None);
            condition_of(&status, CONDITION_TYPE_PROGRAMMED)
                .status
                .clone()
        };
        assert_eq!(programmed(&served, &tls), "False");
        served.https_passthrough = true;
        assert_eq!(programmed(&served, &tls), "True");
        assert_eq!(programmed(&served, &tcp), "False");
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
            ..Default::default()
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

    /// TCP and UDP routes report their status as TLS ones do: `Accepted` on
    /// a parent of ours, `ResolvedRefs` from their backends.
    #[test]
    fn tcp_and_udp_routes_report_their_status() {
        let condition = |parents: Vec<Condition>, type_: &str| {
            let c = parents.into_iter().find(|c| c.type_ == type_).unwrap();
            (c.status, c.reason)
        };

        let scope = tcp_scope(9000);
        let route = tcp_route(9000);
        assert_eq!(
            l4_outcome(&route, true, &r1(), &scope),
            RouteOutcome::Accepted
        );
        assert_eq!(
            l4_outcome(&route, true, &r0(), &scope),
            RouteOutcome::NoResolvableBackends
        );
        let parents = route.build_status(&scope, RouteOutcome::Accepted, None);
        assert_eq!(parents.len(), 1);
        let conditions = parents[0].conditions.clone().unwrap();
        assert_eq!(
            condition(conditions.clone(), CONDITION_TYPE_ACCEPTED),
            ("True".to_string(), REASON_ACCEPTED.to_string())
        );
        assert_eq!(
            condition(conditions, CONDITION_TYPE_RESOLVED_REFS),
            ("True".to_string(), REASON_RESOLVED_REFS.to_string())
        );
        let unready = route.build_status(&scope, RouteOutcome::NoResolvableBackends, None);
        assert_eq!(
            condition(
                unready[0].conditions.clone().unwrap(),
                CONDITION_TYPE_RESOLVED_REFS
            ),
            ("False".to_string(), REASON_BACKEND_NOT_FOUND.to_string())
        );

        let scope = udp_scope(53);
        let mut route = udp_route(53);
        route.spec.rules[0].backend_refs.as_mut().unwrap()[0].namespace = Some("other".into());
        let invalid = l4_route_invalid_ref(&route, &r1(), &scope);
        assert_eq!(invalid, Some(InvalidRef::NotPermitted));
        let parents = route.build_status(&scope, RouteOutcome::Accepted, invalid);
        assert_eq!(
            condition(
                parents[0].conditions.clone().unwrap(),
                CONDITION_TYPE_RESOLVED_REFS
            ),
            ("False".to_string(), REASON_REF_NOT_PERMITTED.to_string())
        );
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
            &tcp_ports(),
            None
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

        apply_tcp_route(&route, &storage, &index, &r1(), &scope, &tcp_ports(), None);
        assert!(storage.read().unwrap().is_empty());
        assert_eq!(index.read().unwrap().len(), 1);

        // Declare 9443 and re-resolve: the route lands.
        let ports = Arc::new([(9443, "tcpgw".to_string())].into_iter().collect());
        assert!(re_resolve_all_tcp(
            &storage,
            &index,
            &r1(),
            &scope,
            &ports,
            None
        ));
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
            &udp_ports(),
            None
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
            ..Default::default()
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
    fn gateway_durations_are_read_in_milliseconds() {
        assert_eq!(gateway_duration_ms("500ms"), Some(500));
        assert_eq!(gateway_duration_ms("1s"), Some(1_000));
        assert_eq!(gateway_duration_ms("1h2m3s4ms"), Some(3_723_004));
        assert_eq!(gateway_duration_ms("0s"), Some(0));
        for invalid in ["", "1", "s", "1d", "1.5s"] {
            assert_eq!(gateway_duration_ms(invalid), None, "{invalid}");
        }
    }

    /// `request` bounds the whole request, `backendRequest` each attempt; a
    /// zero `backendRequest` disables the backend timeout.
    #[test]
    fn rule_timeouts_map_to_request_and_backend_timeouts() {
        use gateway_api::apis::standard::httproutes::HTTPRouteRulesTimeouts;
        let with = |request: Option<&str>, backend_request: Option<&str>| {
            let mut r = rule(None, vec![backend("api", 80)]);
            r.timeouts = Some(HTTPRouteRulesTimeouts {
                request: request.map(String::from),
                backend_request: backend_request.map(String::from),
            });
            let route = route_with(vec![r], vec!["app.example.com".into()]);
            let config = &route_to_entrypoints(&route, &r1(), &AllowAllBackendRefs)[0].config;
            (config.request_timeout, config.backend_timeout)
        };
        assert_eq!(with(Some("2s"), Some("500ms")), (Some(2_000), Some(500)));
        assert_eq!(with(Some("0s"), None), (None, None));
        assert_eq!(with(None, Some("0s")), (None, Some(0)));
        assert_eq!(with(None, Some("1m")), (None, Some(60_000)));
    }

    /// A redirect on a condition only the middleware checks would skip it:
    /// such an entrypoint is flagged, so the route is refused.
    #[test]
    fn a_redirect_on_middleware_conditions_is_flagged() {
        let mut ep = route_to_entrypoints(
            &route_with(
                vec![rule(None, vec![backend("api", 80)])],
                vec!["app.example.com".into()],
            ),
            &r1(),
            &AllowAllBackendRefs,
        )
        .remove(0);
        ep.config.redirect = Some(RedirectPolicy::Permanent);
        assert!(!redirect_skips_conditions(&ep));
        ep.config.match_headers = vec![crate::model::MatchCondition {
            key: "Cookie".into(),
            value: "beta=1".into(),
            regex: false,
        }];
        assert!(redirect_skips_conditions(&ep));
    }

    /// A prefix replacement on an exact match is refused, as Gateway API says.
    #[test]
    fn a_prefix_replacement_on_an_exact_match_is_refused() {
        use gateway_api::apis::standard::httproutes::{
            HTTPRouteRulesFiltersRequestRedirect, HTTPRouteRulesFiltersRequestRedirectPath,
            HTTPRouteRulesFiltersRequestRedirectPathType,
        };
        let redirect = |path_type| {
            let mut r = rule(
                Some(vec![path_match("/original", path_type)]),
                vec![backend("api", 80)],
            );
            r.filters = Some(vec![HTTPRouteRulesFilters {
                request_redirect: Some(HTTPRouteRulesFiltersRequestRedirect {
                    path: Some(HTTPRouteRulesFiltersRequestRedirectPath {
                        replace_full_path: None,
                        replace_prefix_match: Some("/replacement".into()),
                        r#type: HTTPRouteRulesFiltersRequestRedirectPathType::ReplacePrefixMatch,
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }]);
            route_with(vec![r], vec!["app.example.com".into()])
        };
        assert!(route_has_unsupported_filters(
            &redirect(HTTPRouteRulesMatchesPathType::Exact),
            &r1(),
            &AllowAllBackendRefs
        ));
        assert!(!route_has_unsupported_filters(
            &redirect(HTTPRouteRulesMatchesPathType::PathPrefix),
            &r1(),
            &AllowAllBackendRefs
        ));
    }

    /// A redirect replacing the matched prefix carries it as a rewrite, which
    /// builds the `Location` path.
    #[test]
    fn a_prefix_redirect_rewrites_the_location_path() {
        use gateway_api::apis::standard::httproutes::{
            HTTPRouteRulesFiltersRequestRedirect, HTTPRouteRulesFiltersRequestRedirectPath,
            HTTPRouteRulesFiltersRequestRedirectPathType,
        };
        let mut r = rule(
            Some(vec![path_match(
                "/original",
                HTTPRouteRulesMatchesPathType::PathPrefix,
            )]),
            vec![backend("api", 80)],
        );
        r.filters = Some(vec![HTTPRouteRulesFilters {
            request_redirect: Some(HTTPRouteRulesFiltersRequestRedirect {
                path: Some(HTTPRouteRulesFiltersRequestRedirectPath {
                    replace_full_path: None,
                    replace_prefix_match: Some("/replacement".into()),
                    r#type: HTTPRouteRulesFiltersRequestRedirectPathType::ReplacePrefixMatch,
                }),
                ..Default::default()
            }),
            ..Default::default()
        }]);
        let route = route_with(vec![r], vec!["app.example.com".into()]);
        let ep = &route_to_entrypoints(&route, &r1(), &AllowAllBackendRefs)[0];
        assert_eq!(ep.config.redirect, Some(RedirectPolicy::Permanent));
        assert_eq!(
            ep.config.rewrite,
            Some(UrlRewrite {
                path: Some(PathRewrite::ReplacePrefixMatch("/replacement".into())),
                hostname: None,
            })
        );
    }

    /// Only the backendRefs that can take traffic must agree on filters: a
    /// weight-0 one with others does not drop the route.
    #[test]
    fn unusable_backend_refs_do_not_have_to_agree_on_filters() {
        use gateway_api::apis::standard::httproutes::{
            HTTPRouteRulesBackendRefsFilters,
            HTTPRouteRulesBackendRefsFiltersRequestHeaderModifier,
            HTTPRouteRulesBackendRefsFiltersRequestHeaderModifierSet,
        };
        let set = |value: &str| {
            Some(vec![HTTPRouteRulesBackendRefsFilters {
                request_header_modifier: Some(
                    HTTPRouteRulesBackendRefsFiltersRequestHeaderModifier {
                        set: Some(vec![
                            HTTPRouteRulesBackendRefsFiltersRequestHeaderModifierSet {
                                name: "X-Backend".into(),
                                value: value.into(),
                            },
                        ]),
                        ..Default::default()
                    },
                ),
                ..Default::default()
            }])
        };
        let mut serving = backend("api", 80);
        serving.filters = set("api");
        let mut idle = backend("idle", 80);
        idle.filters = set("idle");
        idle.weight = Some(0);
        let route = route_with(
            vec![rule(None, vec![serving, idle])],
            vec!["app.example.com".into()],
        );
        assert!(!route_has_unsupported_filters(
            &route,
            &r1(),
            &AllowAllBackendRefs
        ));
        let eps = route_to_entrypoints(&route, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps[0].config.headers[0].value, "api");
    }

    /// backendRefs with different filters keep each their own: the
    /// middleware edits what it sends each backend.
    #[test]
    fn backend_refs_keep_filters_of_their_own() {
        use gateway_api::apis::standard::httproutes::{
            HTTPRouteRulesBackendRefsFilters,
            HTTPRouteRulesBackendRefsFiltersRequestHeaderModifier,
            HTTPRouteRulesBackendRefsFiltersRequestHeaderModifierSet,
        };
        let set = |value: &str| {
            Some(vec![HTTPRouteRulesBackendRefsFilters {
                request_header_modifier: Some(
                    HTTPRouteRulesBackendRefsFiltersRequestHeaderModifier {
                        set: Some(vec![
                            HTTPRouteRulesBackendRefsFiltersRequestHeaderModifierSet {
                                name: "X-Backend".into(),
                                value: value.into(),
                            },
                        ]),
                        ..Default::default()
                    },
                ),
                ..Default::default()
            }])
        };
        let mut api = backend("api", 80);
        api.filters = set("api");
        let mut web = backend("web", 80);
        web.filters = set("web");
        let mut shared = rule(None, vec![api, web]);
        shared.filters = Some(vec![HTTPRouteRulesFilters {
            response_header_modifier: Some(
                gateway_api::apis::standard::httproutes::HTTPRouteRulesFiltersResponseHeaderModifier {
                    remove: Some(vec!["Server".into()]),
                    ..Default::default()
                },
            ),
            ..Default::default()
        }]);
        let route = route_with(vec![shared], vec!["app.example.com".into()]);
        assert!(!route_has_unsupported_filters(
            &route,
            &r1(),
            &AllowAllBackendRefs
        ));
        let eps = route_to_entrypoints(&route, &r1(), &AllowAllBackendRefs);
        // The rule's own edits stay the route's.
        assert_eq!(eps[0].config.headers[0].name, "Server");
        let values: Vec<&str> = eps[0]
            .backends
            .iter()
            .map(|b| b.headers[0].value.as_str())
            .collect();
        assert_eq!(values, ["api", "web"]);
        assert!(crate::middleware::needs_middleware(&eps[0]));
    }

    #[test]
    fn a_rule_without_backends_answers_500() {
        let r = route_with(
            vec![HTTPRouteRules {
                backend_refs: None,
                ..Default::default()
            }],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        assert_eq!(
            eps[0].config.answer,
            Some(crate::model::FixedAnswer::InvalidBackends)
        );
    }

    /// A redirect answers by itself: its rule needs no backend.
    #[test]
    fn a_redirect_rule_without_backends_redirects() {
        use gateway_api::apis::standard::httproutes::HTTPRouteRulesFiltersRequestRedirect;
        let r = route_with(
            vec![HTTPRouteRules {
                filters: Some(vec![HTTPRouteRulesFilters {
                    request_redirect: Some(HTTPRouteRulesFiltersRequestRedirect {
                        hostname: Some("example.org".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                backend_refs: None,
                ..Default::default()
            }],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r0(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        assert!(eps[0].backends.is_empty());
        assert!(eps[0].config.answer.is_none());
        assert_eq!(eps[0].config.redirect, Some(RedirectPolicy::Permanent));
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

    /// The share of a backendRef Sōzune cannot use is answered `500`, that
    /// of one with no ready pod `503`, each by its weight.
    #[test]
    fn unusable_backend_refs_keep_their_share_as_errors() {
        struct OnlyApi;
        impl ServiceResolver for OnlyApi {
            fn pod_ips(&self, _namespace: &str, service: &str) -> Vec<String> {
                if service == "api" {
                    vec!["10.0.0.1".into(), "10.0.0.2".into()]
                } else {
                    Vec::new()
                }
            }
        }
        let mut api = backend("api", 80);
        api.weight = Some(6);
        let mut down = backend("down", 80);
        down.weight = Some(2);
        let mut unsupported = backend("bucket", 80);
        unsupported.kind = Some("Bucket".into());
        unsupported.weight = Some(4);
        let shares = |refs| {
            let r = route_with(vec![rule(None, refs)], vec!["app.example.com".into()]);
            route_to_entrypoints(&r, &OnlyApi, &AllowAllBackendRefs)[0]
                .config
                .failing_shares
        };

        assert_eq!(
            shares(vec![api.clone(), down.clone(), unsupported]),
            Some(crate::model::FailingShares {
                forwarded: 3,
                invalid: 2,
                unavailable: 1,
            })
        );
        // Every share forwarded: nothing to answer.
        assert_eq!(shares(vec![api.clone()]), None);
        // A weight of 0 has no share.
        down.weight = Some(0);
        assert_eq!(shares(vec![api.clone(), down.clone()]), None);
        // Nothing forwarded: the errors take every request.
        api.weight = Some(0);
        let mut bucket = backend("bucket", 80);
        bucket.kind = Some("Bucket".into());
        assert_eq!(
            shares(vec![api, bucket]),
            Some(crate::model::FailingShares {
                forwarded: 0,
                invalid: 1,
                unavailable: 0,
            })
        );
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
        // refused and the rule answers 500.
        let scope = GatewayScope::new();
        let eps = route_to_entrypoints(&r, &CrossNsResolver, &scope);
        assert_eq!(eps.len(), 1);
        assert!(eps[0].backends.is_empty());
        assert_eq!(
            eps[0].config.answer,
            Some(crate::model::FixedAnswer::InvalidBackends)
        );
        assert_eq!(
            route_invalid_ref(&r, &CrossNsResolver, &scope),
            Some(InvalidRef::NotPermitted)
        );
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
        assert!(scope.allows_backend_ref("default", "other", "api"));
        assert!(scope.remove_reference_grant(&grant));
        assert!(!scope.allows_backend_ref("default", "other", "api"));
    }

    /// A grant naming a Service opens that one only, and two grants of a
    /// namespace each keep their own.
    #[test]
    fn a_grant_naming_a_service_opens_that_one_only() {
        let scope = GatewayScope::new();
        let mut v1 = reference_grant("other", "default");
        v1.spec.to[0].name = Some("v1".into());
        assert!(scope.upsert_reference_grant(&v1));
        assert!(scope.allows_backend_ref("default", "other", "v1"));
        assert!(!scope.allows_backend_ref("default", "other", "v2"));
        let mut v2 = reference_grant("other", "default");
        v2.metadata.name = Some("grant-v2".into());
        v2.spec.to[0].name = Some("v2".into());
        assert!(scope.upsert_reference_grant(&v2));
        assert!(scope.allows_backend_ref("default", "other", "v2"));
        assert!(scope.remove_reference_grant(&v2));
        assert!(scope.allows_backend_ref("default", "other", "v1"));
        assert!(!scope.allows_backend_ref("default", "other", "v2"));
    }

    #[test]
    fn same_namespace_backend_never_needs_grant() {
        let scope = GatewayScope::new();
        // No grant at all, yet same-namespace is always allowed.
        assert!(scope.allows_backend_ref("app", "app", "api"));
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
        assert!(!scope.allows_backend_ref("default", "other", "api"));
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
        assert!(scope.allows_backend_ref("default", "other", "api"));
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
    fn regex_path_match_is_reported_unsupported() {
        let r = route_with(
            vec![rule(
                Some(vec![path_match(
                    "/api/v[0-9]+",
                    HTTPRouteRulesMatchesPathType::RegularExpression,
                )]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        assert!(route_has_unsupported_matches(&r));
    }

    #[test]
    fn a_regex_that_does_not_compile_is_reported_unsupported() {
        let r = route_with(
            vec![rule(
                Some(vec![header_match(
                    "X-Canary",
                    "v(",
                    HTTPRouteRulesMatchesHeadersType::RegularExpression,
                )]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        assert!(route_has_unsupported_matches(&r));
    }

    /// A regex is checked as it is served, anchored: a trailing extended-mode
    /// comment would swallow the anchors.
    #[test]
    fn a_regex_is_checked_anchored() {
        // A comment swallowing the anchors, and a regex valid only once
        // wrapped, which would take any value starting with `a`.
        for pattern in ["(?x)v # comment", "a)|(?:b"] {
            let r = route_with(
                vec![rule(
                    Some(vec![header_match(
                        "X-Canary",
                        pattern,
                        HTTPRouteRulesMatchesHeadersType::RegularExpression,
                    )]),
                    vec![backend("api", 80)],
                )],
                vec!["app.example.com".into()],
            );
            assert!(route_has_unsupported_matches(&r), "{pattern}");
        }
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
    fn regex_header_match_is_a_regex_condition() {
        let r = route_with(
            vec![rule(
                Some(vec![header_match(
                    "X-Canary",
                    "v[0-9]+",
                    HTTPRouteRulesMatchesHeadersType::RegularExpression,
                )]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        assert!(!route_has_unsupported_matches(&r));
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert!(eps[0].config.match_headers[0].regex);
    }

    #[test]
    fn regex_query_match_is_a_regex_condition() {
        let r = route_with(
            vec![rule(
                Some(vec![query_match(
                    "v",
                    "[0-9]+",
                    HTTPRouteRulesMatchesQueryParamsType::RegularExpression,
                )]),
                vec![backend("api", 80)],
            )],
            vec!["app.example.com".into()],
        );
        assert!(!route_has_unsupported_matches(&r));
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert!(eps[0].config.match_query[0].regex);
        // Left to the middleware: Sōzu routes on literal query values only.
        assert!(crate::middleware::needs_middleware(&eps[0]));
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
    fn a_rule_of_non_service_backends_answers_500() {
        let mut b = backend("svc", 80);
        b.kind = Some("CustomResource".into());
        let r = route_with(vec![rule(None, vec![b])], vec!["app.example.com".into()]);
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        assert!(eps[0].backends.is_empty());
        assert_eq!(
            eps[0].config.answer,
            Some(crate::model::FixedAnswer::InvalidBackends)
        );
        assert_eq!(
            route_invalid_ref(&r, &r1(), &AllowAllBackendRefs),
            Some(InvalidRef::Kind)
        );
    }

    /// An invalid backendRef next to a valid one leaves the rule to the
    /// valid one.
    #[test]
    fn a_valid_backend_ref_serves_next_to_an_invalid_one() {
        let mut b = backend("svc", 80);
        b.kind = Some("CustomResource".into());
        let r = route_with(
            vec![rule(None, vec![b, backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        assert!(!eps[0].backends.is_empty());
        assert!(eps[0].config.answer.is_none());
    }

    /// A Service known not to exist is invalid; one not known yet is not.
    #[test]
    fn a_missing_service_is_invalid_once_services_are_known() {
        struct Known(Option<bool>);
        impl ServiceResolver for Known {
            fn pod_ips(&self, _namespace: &str, _service: &str) -> Vec<String> {
                Vec::new()
            }
            fn service_exists(&self, _namespace: &str, _service: &str) -> Option<bool> {
                self.0
            }
        }
        let r = route_with(
            vec![rule(None, vec![backend("ghost", 80)])],
            vec!["app.example.com".into()],
        );
        let eps = route_to_entrypoints(&r, &Known(Some(false)), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        assert_eq!(
            eps[0].config.answer,
            Some(crate::model::FixedAnswer::InvalidBackends)
        );
        assert!(route_to_entrypoints(&r, &Known(None), &AllowAllBackendRefs).is_empty());
        assert_eq!(
            route_invalid_ref(&r, &Known(None), &AllowAllBackendRefs),
            None
        );
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

        // v2's backends have no ready endpoint — the entrypoint must
        // disappear from storage, but the route stays in the index so the
        // periodic re-resolve can revive it once endpoints come back.
        let v2 = route_with_uid(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        let changed = apply_route(&v2, &storage, &index, &r0(), &scope, None);
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
                .map(|i| (format!("10.{}.{}.{}", pods % 256, i / 256, i % 256), 80))
                .collect(),
            headers: Vec::new(),
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
        assert!(route_has_unsupported_filters(
            &r,
            &r1(),
            &AllowAllBackendRefs
        ));
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
        assert!(!route_has_unsupported_filters(
            &r,
            &r1(),
            &AllowAllBackendRefs
        ));
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
        assert!(!route_has_unsupported_filters(
            &r,
            &r1(),
            &AllowAllBackendRefs
        ));
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
        assert!(!route_has_unsupported_filters(
            &r,
            &r1(),
            &AllowAllBackendRefs
        ));
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
        assert!(!route_has_unsupported_filters(
            &r,
            &r1(),
            &AllowAllBackendRefs
        ));
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].config.redirect, Some(RedirectPolicy::Permanent));
        assert_eq!(eps[0].config.headers.len(), 1);
    }

    /// A `requestMirror` is served: the rule's entrypoints copy their
    /// requests to the mirror's pods, through the middleware.
    #[test]
    fn route_with_request_mirror_copies_its_requests() {
        use gateway_api::apis::standard::httproutes::{
            HTTPRouteRulesFiltersRequestMirror, HTTPRouteRulesFiltersRequestMirrorBackendRef,
        };
        let filter = HTTPRouteRulesFilters {
            request_mirror: Some(HTTPRouteRulesFiltersRequestMirror {
                backend_ref: HTTPRouteRulesFiltersRequestMirrorBackendRef {
                    name: "mirror".into(),
                    port: Some(8080),
                    ..Default::default()
                },
            }),
            ..Default::default()
        };
        let r = route_with(
            vec![rule_with_filter(vec![backend("api", 80)], vec![filter])],
            vec!["app.example.com".into()],
        );
        assert!(!route_has_unsupported_filters(
            &r,
            &r1(),
            &AllowAllBackendRefs
        ));
        let eps = route_to_entrypoints(&r, &r1(), &AllowAllBackendRefs);
        assert_eq!(eps.len(), 1);
        let mirrors = &eps[0].config.mirrors;
        assert_eq!(mirrors.len(), 1);
        assert_eq!(mirrors[0].backends.len(), 1);
        assert_eq!(mirrors[0].backends[0].port, 8080);
        assert!(crate::middleware::needs_middleware(&eps[0]));
        // A mirror with no ready pod stays, copying nothing: the route keeps
        // going through the middleware.
        let rule_filters = r.spec.rules.as_ref().unwrap()[0].filters.clone().unwrap();
        let mirrors = rule_mirrors(
            "default",
            "web",
            0,
            &rule_filters,
            &r0(),
            &AllowAllBackendRefs,
        );
        assert_eq!(mirrors.len(), 1);
        assert!(mirrors[0].backends.is_empty());
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
        assert!(!route_has_unsupported_filters(
            &r,
            &r1(),
            &AllowAllBackendRefs
        ));
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
        assert!(!route_has_unsupported_filters(
            &r,
            &r1(),
            &AllowAllBackendRefs
        ));
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
        assert!(route_has_unsupported_filters(
            &r,
            &r1(),
            &AllowAllBackendRefs
        ));
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
        assert!(!route_has_unsupported_filters(
            &r,
            &r1(),
            &AllowAllBackendRefs
        ));
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
        let parents = build_route_status(&r, &scope, RouteOutcome::Accepted, None);
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
        let parents = build_route_status(&r, &scope, RouteOutcome::UnsupportedFilters, None);
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
        let parents = build_route_status(&r, &scope, RouteOutcome::NoResolvableBackends, None);
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
        let parents = build_route_status(&r, &scope, RouteOutcome::NotMine, None);
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
        let parents = build_route_status(&r, &scope, RouteOutcome::Accepted, None);
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

        let parents = build_route_status(&r, &scope, RouteOutcome::NotMine, None);
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].parent_ref.name, "gw");
        let conditions = parents[0].conditions.as_deref().unwrap_or_default();
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0].type_, CONDITION_TYPE_ACCEPTED);
        assert_eq!(conditions[0].status, "False");
        assert_eq!(conditions[0].reason, REASON_NOT_ALLOWED_BY_LISTENERS);
        // The backendRefs are reported on, whether the parent takes the route
        // or not.
        assert_eq!(conditions[1].type_, CONDITION_TYPE_RESOLVED_REFS);
        assert_eq!(conditions[1].status, "True");
    }

    #[test]
    fn build_status_reports_why_a_backend_ref_cannot_be_used() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        scope.upsert_gateway(&gateway("default", "gw", "sozune"));
        let r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent("gw")],
        );
        for (invalid, reason) in [
            (InvalidRef::Kind, REASON_INVALID_KIND),
            (InvalidRef::NotPermitted, REASON_REF_NOT_PERMITTED),
            (InvalidRef::NotFound, REASON_BACKEND_NOT_FOUND),
        ] {
            let parents = build_route_status(&r, &scope, RouteOutcome::Accepted, Some(invalid));
            let conditions = parents[0].conditions.as_deref().unwrap_or_default();
            assert_eq!(conditions[0].status, "True");
            assert_eq!(conditions[1].type_, CONDITION_TYPE_RESOLVED_REFS);
            assert_eq!(conditions[1].status, "False");
            assert_eq!(conditions[1].reason, reason);
        }
    }

    /// An unsupported match refuses the route, without blaming its refs.
    #[test]
    fn build_status_reports_an_unsupported_match() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        scope.upsert_gateway(&gateway("default", "gw", "sozune"));
        let r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent("gw")],
        );
        let parents = build_route_status(&r, &scope, RouteOutcome::UnsupportedMatches, None);
        let conditions = parents[0].conditions.as_deref().unwrap_or_default();
        assert_eq!(conditions[0].status, "False");
        assert_eq!(conditions[0].reason, REASON_UNSUPPORTED_VALUE);
        assert_eq!(conditions[1].status, "True");
    }

    #[test]
    fn build_status_reports_a_route_no_listener_hostname_admits() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        scope.upsert_gateway(&gateway("default", "gw", "sozune"));
        let r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent("gw")],
        );
        let parents =
            build_route_status(&r, &scope, RouteOutcome::NoMatchingListenerHostname, None);
        let conditions = parents[0].conditions.as_deref().unwrap_or_default();
        assert_eq!(conditions[0].status, "False");
        assert_eq!(conditions[0].reason, REASON_NO_MATCHING_LISTENER_HOSTNAME);
        assert_eq!(conditions[1].status, "True");
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
        let ours = build_route_status(&r, &scope, RouteOutcome::Accepted, None);
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
        let first = build_route_status(&r, &scope, RouteOutcome::Accepted, None);
        // Simulate a status write having already happened: the
        // existing object now contains our slice. A second computation
        // of the same outcome should be detected as a no-op.
        let existing = HTTPRouteStatus {
            parents: first.clone(),
        };
        // Sleep a few ms so timestamps actually differ.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let second = build_route_status(&r, &scope, RouteOutcome::Accepted, None);
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
        let accepted = build_route_status(&r, &scope, RouteOutcome::Accepted, None);
        let existing = HTTPRouteStatus {
            parents: accepted.clone(),
        };
        let unsupported = build_route_status(&r, &scope, RouteOutcome::UnsupportedFilters, None);
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
    fn invalid_listeners_mark_the_gateway() {
        use gateway_api::apis::standard::gateways::GatewayStatusListeners;
        let gw = gateway("default", "gw", "sozune");
        let listener = |accepted: bool| GatewayStatusListeners {
            conditions: vec![Condition {
                type_: CONDITION_TYPE_ACCEPTED.to_string(),
                status: if accepted { "True" } else { "False" }.to_string(),
                reason: String::new(),
                message: String::new(),
                last_transition_time: Time(k8s_openapi::chrono::Utc::now()),
                observed_generation: None,
            }],
            ..Default::default()
        };

        let mut conds = build_gateway_conditions(&gw, true);
        mark_invalid_listeners(&mut conds, &[listener(true), listener(false)]);
        assert_eq!(conds[0].status, "True");
        assert_eq!(conds[0].reason, REASON_LISTENERS_NOT_VALID);
        assert_eq!(conds[1].status, "True");
        assert_eq!(conds[1].reason, REASON_PROGRAMMED);

        let mut conds = build_gateway_conditions(&gw, true);
        mark_invalid_listeners(&mut conds, &[listener(false)]);
        assert_eq!(conds[0].status, "False");
        assert_eq!(conds[0].reason, REASON_LISTENERS_NOT_VALID);
        assert_eq!(conds[1].status, "False");
        assert_eq!(conds[1].reason, REASON_INVALID);

        let mut conds = build_gateway_conditions(&gw, true);
        mark_invalid_listeners(&mut conds, &[listener(true)]);
        assert_eq!(conds[0].reason, REASON_ACCEPTED);
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
            https_passthrough: false,
            gateway: crate::config::GatewayPortsConfig {
                tcp: vec!["9000-9099".parse().unwrap()],
                udp: vec!["5353".parse().unwrap()],
                ..Default::default()
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

    /// A certificate stops being used once it expires.
    #[test]
    fn a_listener_drops_its_certificate_once_it_expires() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        let mut api = https_listener("api", None, "api-tls");
        api.hostname = Some("api.example.com".into());
        gw.spec.listeners = vec![api];
        scope.upsert_gateway(&gw);
        // Whatever names it covers: a Gateway's certificateRefs are not
        // checked against its listener's hostname.
        store_secret(&scope, "default", "api-tls", "other.example.com");
        assert_eq!(resolved_refs(&scope, &gw, "api").status, "True");
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

    /// Removing a GatewayClass drops its own Gateways, not those of the
    /// other classes Sōzune owns.
    #[test]
    fn removing_a_class_keeps_the_gateways_of_the_others() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        scope.upsert_gateway_class(&class("other", SOZUNE_CONTROLLER_NAME));
        scope.upsert_gateway(&gateway("default", "kept", "sozune"));
        scope.upsert_gateway(&gateway("default", "gone", "other"));

        scope.remove_gateway_class("other");
        let route = |gw: &str| {
            route_with_parents(
                vec![rule(None, vec![backend("api", 80)])],
                vec!["a.example.com".into()],
                vec![parent(gw)],
            )
        };
        assert!(scope.accepts_route(&route("kept")));
        assert!(!scope.accepts_route(&route("gone")));
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
        assert!(scope.allows_backend_ref("frontend", "backend", "api"));
        scope.retain_reference_grants(std::slice::from_ref(&grant));
        assert!(scope.allows_backend_ref("frontend", "backend", "api"));
        scope.retain_reference_grants(&[]);
        assert!(!scope.allows_backend_ref("frontend", "backend", "api"));
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
            route_entrypoints_by_scheme(
                &route,
                &r1(),
                &AllowAllBackendRefs,
                plain,
                secure,
                None,
                None,
            )
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
                (
                    id.clone(),
                    vec!["/.+/.example.com".to_string()],
                    false,
                    false
                ),
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
                    vec!["/.+/.example.com".to_string()],
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
                (id.clone(), vec!["*".to_string()], false, false),
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
                (format!("{id}-https"), vec!["*".to_string()], true, true),
            ]
        );
    }

    /// A route's wildcard hostnames get entrypoints of their own, so each is
    /// ordered after the exact names of other routes.
    #[test]
    fn wildcard_hostnames_are_split_from_exact_ones() {
        let route = route_with_parents(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["a.example.com".into()],
            vec![parent("gw")],
        );
        let hosts: Vec<(String, Vec<String>)> = route_entrypoints_by_scheme(
            &route,
            &r1(),
            &AllowAllBackendRefs,
            Some(vec![
                "a.example.com".into(),
                "*.example.com".into(),
                "b.example.com".into(),
            ]),
            None,
            None,
            None,
        )
        .into_iter()
        .map(|ep| (ep.id, ep.config.hostnames))
        .collect();
        let id = format!("{SOURCE_TAG}-default-web-0");
        assert_eq!(
            hosts,
            [
                (
                    format!("{id}-h0"),
                    vec!["a.example.com".to_string(), "b.example.com".to_string()]
                ),
                // A Gateway API wildcard takes any number of labels.
                (format!("{id}-h1"), vec!["/.+/.example.com".to_string()]),
            ]
        );
    }

    /// A hostname an HTTPS listener without certificate admits still
    /// matches the listener: the route is not reported as matching none.
    #[test]
    fn a_listener_without_certificate_still_matches_hostnames() {
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        let mut https = https_listener("tls", None, "shop-tls");
        https.hostname = Some("*.shop.example".into());
        gw.spec.listeners = vec![https];
        scope.upsert_gateway(&gw);
        let route = |host: &str| {
            route_with_parents(
                vec![rule(None, vec![backend("api", 80)])],
                vec![host.into()],
                vec![parent("gw")],
            )
        };
        assert!(scope.listener_hostname_matches(&route("www.shop.example")));
        assert!(!scope.listener_hostname_matches(&route("blog.example")));
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
            scope.effective_hostnames_for_route(&route, &GatewayScope::listener_serves_https),
            None
        );
        store_secret(&scope, "default", "shop-tls", "*.shop.example");
        assert_eq!(
            scope.effective_hostnames_for_route(&route, &GatewayScope::listener_serves_https),
            Some(vec!["www.shop.example".to_string()])
        );
        assert_eq!(
            scope.effective_hostnames_for_route(&route, &GatewayScope::listener_is_plain_http),
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
            scope.effective_hostnames_for_route(&only_https, &GatewayScope::listener_is_plain_http),
            None
        );
    }

    /// An HTTP listener on a port of `gateway_ports.http` is served there,
    /// and says so; an unopened one is unavailable; any other is served on
    /// the main HTTP port.
    #[test]
    fn an_http_listener_on_a_port_of_its_own_is_served_there() {
        let gw = gateway("default", "gw", "sozune");
        let mut served = served();
        served.gateway.http = vec!["8080".parse().unwrap()];
        let programmed = |served: &ServedPorts, port: i32| {
            let status = build_listener_status(&gw, &li("l", port, None), served, 0, None);
            let c = condition_of(&status, CONDITION_TYPE_PROGRAMMED);
            (c.status.clone(), c.message.clone())
        };
        assert_eq!(
            programmed(&served, 8080),
            ("True".to_string(), "Sōzune serves port 8080".to_string())
        );
        assert!(programmed(&served, 8090).1.contains("map port 8090"));
        served.unopened.http.insert(8080, "address in use".into());
        let (status, message) = programmed(&served, 8080);
        assert_eq!(status, "False");
        assert!(message.contains("could not open port 8080"), "{message}");
    }

    /// A route served over plain HTTP on a listener of its own port gets no
    /// redirect on the main HTTP port for the names only HTTPS admits there.
    #[test]
    fn a_route_with_plain_http_elsewhere_is_https_only() {
        let route = route_with(
            vec![rule(None, vec![backend("api", 80)])],
            vec!["app.example.com".into()],
        );
        let eps = route_entrypoints_by_scheme(
            &route,
            &r1(),
            &AllowAllBackendRefs,
            None,
            Some(vec!["app.example.com".into(), "public.example.com".into()]),
            None,
            Some(&["app.example.com".to_string()]),
        );
        let by_host = |host: &str| {
            eps.iter()
                .find(|ep| ep.config.hostnames.iter().any(|h| h == host))
                .unwrap()
        };
        // Its plain HTTP is elsewhere: HTTPS alone.
        assert!(by_host("app.example.com").config.https_only);
        assert!(!by_host("app.example.com").config.https_redirect);
        // Not this one: still redirected from the main HTTP port.
        assert!(!by_host("public.example.com").config.https_only);
        assert!(by_host("public.example.com").config.https_redirect);
    }

    /// A wildcard over a name served over plain HTTP elsewhere takes it too:
    /// no redirect for it either.
    #[test]
    fn a_wildcard_over_a_name_served_elsewhere_is_https_only() {
        let route = route_with(vec![rule(None, vec![backend("api", 80)])], Vec::new());
        let eps = route_entrypoints_by_scheme(
            &route,
            &r1(),
            &AllowAllBackendRefs,
            None,
            Some(vec!["*.example.com".into()]),
            None,
            Some(&["admin.example.com".to_string()]),
        );
        assert!(
            eps.iter()
                .all(|ep| ep.config.https_only && !ep.config.https_redirect)
        );
    }

    /// HTTPS on any host next to plain HTTP elsewhere for one name: no
    /// redirect on any host, which would take that name too.
    #[test]
    fn https_on_any_host_with_plain_http_elsewhere_redirects_nothing() {
        let route = route_with(vec![rule(None, vec![backend("api", 80)])], Vec::new());
        let eps = route_entrypoints_by_scheme(
            &route,
            &r1(),
            &AllowAllBackendRefs,
            None,
            Some(Vec::new()),
            None,
            Some(&["admin.example.com".to_string()]),
        );
        assert!(
            eps.iter()
                .all(|ep| !ep.config.https_redirect && ep.config.https_only)
        );
    }

    /// A redirect on a port of its own keeps the port, unless it changes the
    /// scheme or names one.
    #[test]
    fn a_redirect_on_its_own_port_keeps_it() {
        use gateway_api::apis::standard::httproutes::HTTPRouteRulesFiltersRequestRedirect;
        let route = |redirect: HTTPRouteRulesFiltersRequestRedirect| {
            route_with(
                vec![HTTPRouteRules {
                    filters: Some(vec![HTTPRouteRulesFilters {
                        request_redirect: Some(redirect),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }],
                vec!["app.example.com".into()],
            )
        };
        let port_of = |redirect| {
            own_port_entrypoints(
                &route(redirect),
                &r0(),
                &AllowAllBackendRefs,
                8080,
                Vec::new(),
                false,
            )[0]
            .config
            .rewrite_port
        };
        assert_eq!(
            port_of(HTTPRouteRulesFiltersRequestRedirect {
                hostname: Some("example.org".into()),
                ..Default::default()
            }),
            Some(8080)
        );
        assert_eq!(
            port_of(HTTPRouteRulesFiltersRequestRedirect {
                port: Some(9090),
                ..Default::default()
            }),
            Some(9090)
        );
    }

    /// An `HTTPS` listener on a port of `gateway_ports.https` serves its
    /// routes there, over HTTPS alone; one on the main HTTPS port, there.
    #[tokio::test]
    async fn an_https_listener_on_its_own_port_is_served_there() {
        let scope = GatewayScope::new();
        let (tx, _rx) = mpsc::channel(64);
        let mut ports = served();
        ports.gateway.https = vec!["8443".parse().unwrap()];
        scope.configure_status(ports, tx);
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        store_secret(&scope, "default", "cert", "app.example.com");
        let mut gw = gateway("default", "gw", "sozune");
        let mut own = https_listener("own", None, "cert");
        own.port = 8443;
        gw.spec.listeners = vec![https_listener("main", None, "cert"), own];
        scope.upsert_gateway(&gw);

        let on = |section: &str| {
            let mut parent = parent("gw");
            parent.section_name = Some(section.to_string());
            let r = route_with_uid_parents(
                "uid-1",
                vec![rule(None, vec![backend("api", 80)])],
                vec!["app.example.com".into()],
                vec![parent],
            );
            let storage = Arc::new(RwLock::new(BTreeMap::new()));
            let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));
            apply_route(&r, &storage, &index, &r1(), &scope, None);
            storage
                .read()
                .unwrap()
                .values()
                .cloned()
                .collect::<Vec<Entrypoint>>()
        };
        let eps = on("own");
        assert!(!eps.is_empty());
        for ep in &eps {
            assert_eq!(
                ep.config.entrypoint.as_deref(),
                Some(crate::config::gateway_https_listener(8443).as_str())
            );
            assert!(ep.config.tls && ep.config.https_only && !ep.config.https_redirect);
        }
        // On the main HTTPS port: its plain HTTP requests are redirected.
        let eps = on("main");
        assert!(!eps.is_empty());
        for ep in &eps {
            assert_eq!(ep.config.entrypoint, None);
            assert!(ep.config.tls && ep.config.https_redirect);
        }

        let statuses = scope.listener_statuses(&gw);
        let own = statuses.iter().find(|l| l.name == "own").unwrap();
        assert!(
            condition_of(own, CONDITION_TYPE_PROGRAMMED)
                .message
                .contains("serves port 8443")
        );
    }

    /// `HTTPS` listeners on a port of their own are isolated as the plain
    /// HTTP ones are: a route of the wildcard one answers `404`, over HTTPS
    /// on that port, for the host a more specific one takes.
    #[tokio::test]
    async fn https_listeners_on_their_own_port_are_isolated() {
        let scope = GatewayScope::new();
        let (tx, _rx) = mpsc::channel(64);
        let mut ports = served();
        ports.gateway.https = vec!["8443".parse().unwrap()];
        scope.configure_status(ports, tx);
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        store_secret(&scope, "default", "cert", "*.example.com");
        let mut gw = gateway("default", "gw", "sozune");
        let mut wildcard = https_listener("wildcard", None, "cert");
        wildcard.port = 8443;
        wildcard.hostname = Some("*.example.com".into());
        let mut admin = https_listener("admin", None, "cert");
        admin.port = 8443;
        admin.hostname = Some("admin.example.com".into());
        gw.spec.listeners = vec![wildcard, admin];
        scope.upsert_gateway(&gw);

        let mut parent = parent("gw");
        parent.section_name = Some("wildcard".into());
        let r = route_with_uid_parents(
            "uid-1",
            vec![rule(None, vec![backend("api", 80)])],
            Vec::new(),
            vec![parent],
        );
        let storage = Arc::new(RwLock::new(BTreeMap::new()));
        let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));
        apply_route(&r, &storage, &index, &r1(), &scope, None);
        let storage = storage.read().unwrap();
        let shadow = storage
            .values()
            .find(|ep| ep.config.answer == Some(crate::model::FixedAnswer::OtherListener))
            .expect("a 404 entrypoint for admin.example.com");
        assert_eq!(
            shadow.config.hostnames,
            vec!["admin.example.com".to_string()]
        );
        assert!(shadow.config.tls && shadow.config.https_only);
        assert_eq!(
            shadow.config.entrypoint.as_deref(),
            Some(crate::config::gateway_https_listener(8443).as_str())
        );
    }

    /// A route attached to a general listener is kept from the hosts a more
    /// specific listener of the same Gateway and port takes, after that
    /// listener's routes; one attached to both is not.
    #[tokio::test]
    async fn a_route_is_kept_from_the_hosts_of_more_specific_listeners() {
        let scope = GatewayScope::new();
        let (tx, _rx) = mpsc::channel(64);
        scope.configure_status(served(), tx);
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        let mut wildcard = gw_listener("wildcard", 80, "HTTP");
        wildcard.hostname = Some("*.example.com".into());
        let mut abc = gw_listener("abc", 80, "HTTP");
        abc.hostname = Some("abc.foo.example.com".into());
        gw.spec.listeners = vec![gw_listener("empty", 80, "HTTP"), wildcard, abc];
        scope.upsert_gateway(&gw);

        let on = |sections: &[&str]| {
            let parents = sections
                .iter()
                .map(|section| {
                    let mut parent = parent("gw");
                    parent.section_name = Some(section.to_string());
                    parent
                })
                .collect();
            let r = route_with_uid_parents(
                "uid-1",
                vec![rule(
                    Some(vec![path_match(
                        "/x",
                        HTTPRouteRulesMatchesPathType::PathPrefix,
                    )]),
                    vec![backend("api", 80)],
                )],
                Vec::new(),
                parents,
            );
            let storage = Arc::new(RwLock::new(BTreeMap::new()));
            let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));
            apply_route(&r, &storage, &index, &r1(), &scope, None);
            let mut kept: Vec<String> = storage
                .read()
                .unwrap()
                .values()
                .filter(|ep: &&Entrypoint| {
                    ep.config.answer == Some(crate::model::FixedAnswer::OtherListener)
                })
                .map(|ep| ep.config.hostnames[0].clone())
                .collect();
            kept.sort();
            kept
        };
        // On the listener without hostname: both others take hosts from it.
        assert_eq!(
            on(&["empty"]),
            vec!["/.+/.example.com", "abc.foo.example.com"]
        );
        // On the wildcard one: abc.foo.example.com is taken from it.
        assert_eq!(on(&["wildcard"]), vec!["abc.foo.example.com"]);
        // Attached to abc too: it serves that host itself.
        assert!(on(&["wildcard", "abc"]).is_empty());
        // On the most specific one: nothing to keep from.
        assert!(on(&["abc"]).is_empty());

        // Served by another Gateway the route binds on the same port, the
        // host stays.
        let mut other = gateway("default", "other", "sozune");
        let mut abc = gw_listener("abc", 80, "HTTP");
        abc.hostname = Some("abc.foo.example.com".into());
        other.spec.listeners = vec![abc];
        scope.upsert_gateway(&other);
        let mut on_wildcard = parent("gw");
        on_wildcard.section_name = Some("wildcard".into());
        let r = route_with_uid_parents(
            "uid-2",
            vec![rule(None, vec![backend("api", 80)])],
            Vec::new(),
            vec![on_wildcard, parent("other")],
        );
        assert!(scope.isolated_hostnames(&r).is_empty());

        // Taken on each Gateway, by listeners of their own: it goes; one
        // the first Gateway still selects the route for stays.
        let mut parents = Vec::new();
        for (name, host) in [("one", "abc.foo.example.com"), ("two", "*.foo.example.com")] {
            let mut gw = gateway("default", name, "sozune");
            let mut taker = gw_listener("taker", 80, "HTTP");
            taker.hostname = Some(host.into());
            gw.spec.listeners = vec![gw_listener("empty", 80, "HTTP"), taker];
            scope.upsert_gateway(&gw);
            let mut p = parent(name);
            p.section_name = Some("empty".into());
            parents.push(p);
        }
        let r = route_with_uid_parents(
            "uid-3",
            vec![rule(None, vec![backend("api", 80)])],
            Vec::new(),
            parents,
        );
        let mut hosts: Vec<String> = scope
            .isolated_hostnames(&r)
            .into_iter()
            .map(|i| i.host)
            .collect();
        hosts.sort();
        assert_eq!(hosts, vec!["abc.foo.example.com"]);
    }

    fn taken_host(host: &str) -> IsolatedHost {
        IsolatedHost {
            secure: false,
            port: None,
            host: host.into(),
            bound_within: Vec::new(),
        }
    }

    /// A hostname within a listener the route binds, itself within the one
    /// taking it, stays: that listener is the most specific for it.
    #[test]
    fn hostnames_within_a_bound_listener_are_kept() {
        let mut ep = route_to_entrypoints(
            &route_with(
                vec![rule(None, vec![backend("api", 80)])],
                vec!["app.example.com".into()],
            ),
            &r1(),
            &AllowAllBackendRefs,
        )
        .remove(0);
        ep.config.hostnames = vec!["/.+/.example.com".into(), "abc.foo.example.com".into()];
        let out = isolate_from_listeners(
            vec![ep.clone()],
            &[IsolatedHost {
                bound_within: vec!["abc.foo.example.com".into()],
                ..taken_host("*.example.com")
            }],
        );
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].config.hostnames,
            vec!["abc.foo.example.com".to_string()]
        );

        // Broader than the taken one, the route serves the bound host on an
        // entrypoint of its own, ahead of the shadow.
        ep.config.hostnames = vec!["*".into()];
        let out = isolate_from_listeners(
            vec![ep],
            &[IsolatedHost {
                bound_within: vec!["abc.foo.example.com".into()],
                ..taken_host("*.example.com")
            }],
        );
        let hosts: Vec<(&str, Option<crate::model::FixedAnswer>)> = out
            .iter()
            .map(|ep| (ep.config.hostnames[0].as_str(), ep.config.answer))
            .collect();
        assert_eq!(
            hosts,
            vec![
                ("abc.foo.example.com", None),
                ("*", None),
                (
                    "/.+/.example.com",
                    Some(crate::model::FixedAnswer::OtherListener)
                ),
            ]
        );
    }

    /// A hostname wholly within a more specific listener's is dropped, and
    /// the entrypoint with it when none is left; a broader one is kept from
    /// it by a `404` entrypoint.
    #[test]
    fn hostnames_within_a_more_specific_listener_are_dropped() {
        assert!(host_within("abc.foo.example.com", "abc.foo.example.com"));
        assert!(host_within("abc.foo.example.com", "*.foo.example.com"));
        assert!(host_within("/.+/.foo.example.com", "*.foo.example.com"));
        assert!(host_within("/.+/.bar.foo.example.com", "*.foo.example.com"));
        assert!(!host_within("/.+/.example.com", "*.foo.example.com"));
        assert!(!host_within("*", "abc.foo.example.com"));

        let mut ep = route_to_entrypoints(
            &route_with(
                vec![rule(None, vec![backend("api", 80)])],
                vec!["app.example.com".into()],
            ),
            &r1(),
            &AllowAllBackendRefs,
        )
        .remove(0);
        ep.config.hostnames = vec!["abc.foo.example.com".into(), "/.+/.example.com".into()];
        let out = isolate_from_listeners(vec![ep.clone()], &[taken_host("abc.foo.example.com")]);
        assert_eq!(out.len(), 2);
        assert_eq!(
            out[0].config.hostnames,
            vec!["/.+/.example.com".to_string()]
        );
        assert_eq!(
            out[1].config.hostnames,
            vec!["abc.foo.example.com".to_string()]
        );
        assert_eq!(
            out[1].config.answer,
            Some(crate::model::FixedAnswer::OtherListener)
        );

        ep.config.hostnames = vec!["abc.foo.example.com".into()];
        assert!(
            isolate_from_listeners(vec![ep.clone()], &[taken_host("abc.foo.example.com")])
                .is_empty()
        );

        // Served over HTTPS too: the host stays, over HTTPS alone.
        ep.config.tls = true;
        let out = isolate_from_listeners(vec![ep], &[taken_host("abc.foo.example.com")]);
        assert_eq!(out.len(), 1);
        assert!(out[0].config.https_only);
        assert_eq!(
            out[0].config.hostnames,
            vec!["abc.foo.example.com".to_string()]
        );
    }

    /// A route on an HTTP listener with a port of its own is served on that
    /// port's listener; one on another listener, on the main port.
    #[tokio::test]
    async fn routes_follow_their_listener_port() {
        let scope = GatewayScope::new();
        let (tx, _rx) = mpsc::channel(64);
        let mut served = served();
        served.gateway.http = vec!["8080".parse().unwrap()];
        scope.configure_status(served, tx);
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        gw.spec.listeners = vec![
            gw_listener("web", 80, "HTTP"),
            gw_listener("admin", 8080, "HTTP"),
        ];
        scope.upsert_gateway(&gw);

        let on = |section: &str| {
            let mut parent = parent("gw");
            parent.section_name = Some(section.into());
            let r = route_with_uid_parents(
                "uid-1",
                vec![rule(None, vec![backend("api", 80)])],
                vec!["app.example.com".into()],
                vec![parent],
            );
            let storage = Arc::new(RwLock::new(BTreeMap::new()));
            let index: RouteIndex = Arc::new(RwLock::new(HashMap::new()));
            apply_route(&r, &storage, &index, &r1(), &scope, None);
            let eps: Vec<(String, Option<String>)> = storage
                .read()
                .unwrap()
                .values()
                .map(|ep: &Entrypoint| (ep.id.clone(), ep.config.entrypoint.clone()))
                .collect();
            eps
        };
        let admin = on("admin");
        assert_eq!(admin.len(), 1);
        assert!(admin[0].0.ends_with("-p8080"), "{admin:?}");
        assert_eq!(admin[0].1.as_deref(), Some("gateway:http:8080"));
        let web = on("web");
        assert_eq!(web.len(), 1);
        assert_eq!(web[0].1, None);
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
    fn a_namespace_selector_admits_the_namespaces_it_matches() {
        use gateway_api::apis::standard::gateways::{
            GatewayListenersAllowedRoutesNamespacesSelector,
            GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions,
        };
        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("infra", "gw", "sozune");
        let mut allowed = allowed_from(GatewayListenersAllowedRoutesNamespacesFrom::Selector);
        allowed.namespaces.as_mut().unwrap().selector =
            Some(GatewayListenersAllowedRoutesNamespacesSelector {
                match_labels: Some(BTreeMap::from([("team".into(), "web".into())])),
                match_expressions: Some(vec![
                    GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions {
                        key: "env".into(),
                        operator: "NotIn".into(),
                        values: Some(vec!["test".into()]),
                    },
                ]),
            });
        gw.spec.listeners[0].allowed_routes = Some(allowed);
        scope.upsert_gateway(&gw);

        let route_in = |ns: &str| {
            let mut r = route_with_parents(
                vec![rule(None, vec![backend("api", 80)])],
                vec!["a.example.com".into()],
                vec![HTTPRouteParentRefs {
                    name: "gw".into(),
                    namespace: Some("infra".into()),
                    ..Default::default()
                }],
            );
            r.metadata.namespace = Some(ns.into());
            r
        };
        let labels = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        // Namespace labels not known yet: nothing is admitted.
        assert!(!scope.accepts_route(&route_in("shop")));

        scope.set_namespace_labels("shop", Some(labels(&[("team", "web")])));
        scope.set_namespace_labels("qa", Some(labels(&[("team", "web"), ("env", "test")])));
        scope.set_namespace_labels("data", Some(labels(&[("team", "data")])));
        assert!(scope.accepts_route(&route_in("shop")));
        assert!(!scope.accepts_route(&route_in("qa")));
        assert!(!scope.accepts_route(&route_in("data")));

        // A relabelled namespace follows.
        scope.set_namespace_labels("data", Some(labels(&[("team", "web")])));
        assert!(scope.accepts_route(&route_in("data")));
        scope.replace_namespace_labels(HashMap::from([(
            "shop".to_string(),
            labels(&[("team", "web")]),
        )]));
        assert!(scope.accepts_route(&route_in("shop")));
        assert!(!scope.accepts_route(&route_in("data")));
    }

    #[test]
    fn only_a_refusal_counts_as_forbidden() {
        let response = |code: u16| kube::error::ErrorResponse {
            status: "Failure".into(),
            message: String::new(),
            reason: String::new(),
            code,
        };
        assert!(is_forbidden(&watcher::Error::WatchError(response(403))));
        assert!(is_forbidden(&watcher::Error::InitialListFailed(
            kube::Error::Api(response(401))
        )));
        assert!(!is_forbidden(&watcher::Error::WatchError(response(500))));
        assert!(!is_forbidden(&watcher::Error::NoResourceVersion));
    }

    /// A selector Sōzune cannot read, or none at all, admits no route.
    #[test]
    fn a_missing_or_unknown_selector_admits_no_route() {
        use gateway_api::apis::standard::gateways::{
            GatewayListenersAllowedRoutesNamespacesSelector,
            GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions,
        };
        let expression = |operator: &str, values: Option<Vec<String>>| {
            NamespaceSelector::of(&GatewayListenersAllowedRoutesNamespacesSelector {
                match_labels: None,
                match_expressions: Some(vec![
                    GatewayListenersAllowedRoutesNamespacesSelectorMatchExpressions {
                        key: "env".into(),
                        operator: operator.into(),
                        values,
                    },
                ]),
            })
        };
        assert!(expression("Gt", None).is_none());
        // `NotIn` with no value would match every namespace.
        assert!(expression("NotIn", None).is_none());
        assert!(expression("Exists", Some(vec!["x".into()])).is_none());
        assert!(expression("NotIn", Some(vec!["test".into()])).is_some());

        let scope = GatewayScope::new();
        scope.upsert_gateway_class(&class("sozune", SOZUNE_CONTROLLER_NAME));
        let mut gw = gateway("default", "gw", "sozune");
        gw.spec.listeners[0].allowed_routes = Some(allowed_from(
            GatewayListenersAllowedRoutesNamespacesFrom::Selector,
        ));
        scope.upsert_gateway(&gw);
        scope.set_namespace_labels("default", Some(BTreeMap::new()));
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
        let parents = build_route_status(&r, &scope, RouteOutcome::NotMine, None);
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
            let parents = build_route_status(&r, &scope, RouteOutcome::NotMine, None);
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
