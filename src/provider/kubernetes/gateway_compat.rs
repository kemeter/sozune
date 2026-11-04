//! Gateway API resources at the versions every supported release serves.
//!
//! The `gateway-api` crate types them from the latest release only: its
//! ReferenceGrant is `v1`, which Gateway API v1.2 does not serve, and its
//! TLSRoute, TCPRoute and UDPRoute require fields older CRDs leave optional —
//! a route without `hostnames` or `backendRefs`, or a status entry without
//! `conditions`, would fail to deserialize and stall its whole watcher. These
//! types read ReferenceGrant as `v1beta1`, and TLSRoute, TCPRoute and
//! UDPRoute as `v1` or `v1alpha2`, whichever the cluster serves (see
//! [`ServedVersion`]), all with those fields optional.

use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};

use k8s_openapi::NamespaceResourceScope;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, ObjectMeta};
use kube::{CustomResource, Resource};
use serde::{Deserialize, Serialize};

/// Lets resources of other namespaces reference resources of its own.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1beta1",
    kind = "ReferenceGrant",
    plural = "referencegrants",
    namespaced,
    schema = "disabled",
    derive = "Default",
    derive = "PartialEq"
)]
pub struct ReferenceGrantSpec {
    pub from: Vec<ReferenceGrantFrom>,
    pub to: Vec<ReferenceGrantTo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ReferenceGrantFrom {
    pub group: String,
    pub kind: String,
    pub namespace: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ReferenceGrantTo {
    pub group: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// An L4 route kind whose version is chosen at runtime.
///
/// Gateway API v1.5 promoted TLSRoute to `v1`, and v1.6 TCPRoute and UDPRoute:
/// the standard bundle of those releases serves `v1` only, older bundles
/// `v1alpha2` only. Each watcher probes for `v1` first and falls back to
/// `v1alpha2` before it lists, so these kinds are not `CustomResource`s: both
/// versions share their shape, `v1` only making required what `v1alpha2`
/// leaves optional.
pub trait ServedVersion {
    /// Read and write this kind as `v1alpha2` (`true`) or `v1` (`false`).
    /// An `Api` keeps the URL of the version current when it is built.
    fn use_v1alpha2(v1alpha2: bool);
}

/// The types of one route kind, named as the `gateway-api` crate names them.
macro_rules! l4_route {
    (
        $kind:literal, $plural:literal, $route:ident, $flag:ident, $spec:ident, $status:ident,
        $parent_ref:ident, $rule:ident, $backend_ref:ident, $status_parent:ident,
        $status_parent_ref:ident, { $($spec_field:tt)* }
    ) => {
        /// Whether the cluster serves this kind at `v1alpha2` rather than `v1`.
        static $flag: AtomicBool = AtomicBool::new(false);

        #[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
        pub struct $route {
            #[serde(default)]
            pub metadata: ObjectMeta,
            pub spec: $spec,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub status: Option<$status>,
        }

        impl ServedVersion for $route {
            fn use_v1alpha2(v1alpha2: bool) {
                $flag.store(v1alpha2, Ordering::Relaxed);
            }
        }

        impl Resource for $route {
            type DynamicType = ();
            type Scope = NamespaceResourceScope;

            fn kind(_: &()) -> Cow<'_, str> {
                $kind.into()
            }

            fn group(_: &()) -> Cow<'_, str> {
                "gateway.networking.k8s.io".into()
            }

            fn version(_: &()) -> Cow<'_, str> {
                if $flag.load(Ordering::Relaxed) {
                    "v1alpha2".into()
                } else {
                    "v1".into()
                }
            }

            fn plural(_: &()) -> Cow<'_, str> {
                $plural.into()
            }

            fn meta(&self) -> &ObjectMeta {
                &self.metadata
            }

            fn meta_mut(&mut self) -> &mut ObjectMeta {
                &mut self.metadata
            }
        }

        #[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
        pub struct $spec {
            $($spec_field)*
            #[serde(default, skip_serializing_if = "Option::is_none", rename = "parentRefs")]
            pub parent_refs: Option<Vec<$parent_ref>>,
            pub rules: Vec<$rule>,
        }

        l4_route_parts!(
            $status, $parent_ref, $rule, $backend_ref, $status_parent, $status_parent_ref
        );
    };
}

/// The types of a route kind below its spec.
macro_rules! l4_route_parts {
    (
        $status:ident, $parent_ref:ident, $rule:ident, $backend_ref:ident, $status_parent:ident,
        $status_parent_ref:ident
    ) => {
        #[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
        pub struct $parent_ref {
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub group: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub kind: Option<String>,
            pub name: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub namespace: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub port: Option<i32>,
            #[serde(
                default,
                skip_serializing_if = "Option::is_none",
                rename = "sectionName"
            )]
            pub section_name: Option<String>,
        }

        #[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
        pub struct $rule {
            #[serde(
                default,
                skip_serializing_if = "Option::is_none",
                rename = "backendRefs"
            )]
            pub backend_refs: Option<Vec<$backend_ref>>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub name: Option<String>,
        }

        #[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
        pub struct $backend_ref {
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub group: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub kind: Option<String>,
            pub name: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub namespace: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub port: Option<i32>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub weight: Option<i32>,
        }

        #[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
        pub struct $status {
            #[serde(default)]
            pub parents: Vec<$status_parent>,
        }

        #[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
        pub struct $status_parent {
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub conditions: Option<Vec<Condition>>,
            #[serde(rename = "controllerName")]
            pub controller_name: String,
            #[serde(rename = "parentRef")]
            pub parent_ref: $status_parent_ref,
        }

        #[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
        pub struct $status_parent_ref {
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub group: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub kind: Option<String>,
            pub name: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub namespace: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub port: Option<i32>,
            #[serde(
                default,
                skip_serializing_if = "Option::is_none",
                rename = "sectionName"
            )]
            pub section_name: Option<String>,
        }
    };
}

l4_route!(
    "TLSRoute", "tlsroutes", TlsRoute, TLS_ROUTE_V1ALPHA2, TlsRouteSpec, TlsRouteStatus,
    TlsRouteParentRefs, TlsRouteRules, TlsRouteRulesBackendRefs, TlsRouteStatusParents,
    TlsRouteStatusParentsParentRef, {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hostnames: Option<Vec<String>>,
    }
);

l4_route!(
    "TCPRoute",
    "tcproutes",
    TcpRoute,
    TCP_ROUTE_V1ALPHA2,
    TcpRouteSpec,
    TcpRouteStatus,
    TcpRouteParentRefs,
    TcpRouteRules,
    TcpRouteRulesBackendRefs,
    TcpRouteStatusParents,
    TcpRouteStatusParentsParentRef,
    {}
);

l4_route!(
    "UDPRoute",
    "udproutes",
    UdpRoute,
    UDP_ROUTE_V1ALPHA2,
    UdpRouteSpec,
    UdpRouteStatus,
    UdpRouteParentRefs,
    UdpRouteRules,
    UdpRouteRulesBackendRefs,
    UdpRouteStatusParents,
    UdpRouteStatusParentsParentRef,
    {}
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_routes_use_the_version_the_cluster_serves() {
        assert_eq!(
            TcpRoute::url_path(&(), Some("ns")),
            "/apis/gateway.networking.k8s.io/v1/namespaces/ns/tcproutes"
        );
        TcpRoute::use_v1alpha2(true);
        let v1alpha2 = TcpRoute::url_path(&(), Some("ns"));
        TcpRoute::use_v1alpha2(false);
        assert_eq!(
            v1alpha2,
            "/apis/gateway.networking.k8s.io/v1alpha2/namespaces/ns/tcproutes"
        );
    }

    #[test]
    fn tls_routes_use_the_version_the_cluster_serves() {
        assert_eq!(
            TlsRoute::url_path(&(), Some("ns")),
            "/apis/gateway.networking.k8s.io/v1/namespaces/ns/tlsroutes"
        );
        TlsRoute::use_v1alpha2(true);
        let v1alpha2 = TlsRoute::url_path(&(), Some("ns"));
        TlsRoute::use_v1alpha2(false);
        assert_eq!(
            v1alpha2,
            "/apis/gateway.networking.k8s.io/v1alpha2/namespaces/ns/tlsroutes"
        );
    }

    #[test]
    fn a_v1_tls_route_deserializes() {
        let route: TlsRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "TLSRoute",
            "metadata": { "name": "r", "namespace": "default" },
            "spec": {
                "hostnames": ["a.example.com"],
                "parentRefs": [{ "name": "gw", "sectionName": "tls" }],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 443 }] }]
            }
        }))
        .unwrap();
        assert_eq!(
            route.spec.hostnames,
            Some(vec!["a.example.com".to_string()])
        );
        assert_eq!(
            route.spec.rules[0].backend_refs.as_ref().unwrap()[0].port,
            Some(443)
        );
    }

    #[test]
    fn a_route_without_optional_fields_deserializes() {
        let route: TlsRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1alpha2",
            "kind": "TLSRoute",
            "metadata": { "name": "r", "namespace": "default" },
            "spec": { "rules": [{}] },
            "status": { "parents": [{
                "controllerName": "example.com/other",
                "parentRef": { "name": "gw" }
            }] }
        }))
        .unwrap();
        assert_eq!(route.spec.hostnames, None);
        assert_eq!(route.spec.rules[0].backend_refs, None);
        assert_eq!(route.status.unwrap().parents[0].conditions, None);
    }
}
