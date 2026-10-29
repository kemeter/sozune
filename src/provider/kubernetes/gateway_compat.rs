//! Gateway API resources at the versions every supported release serves.
//!
//! The `gateway-api` crate types them from the latest release only: its
//! ReferenceGrant is `v1`, which Gateway API v1.2 does not serve, and its
//! TLSRoute, TCPRoute and UDPRoute require fields older CRDs leave optional —
//! a route without `hostnames` or `backendRefs`, or a status entry without
//! `conditions`, would fail to deserialize and stall its whole watcher. These
//! types read ReferenceGrant as `v1beta1`, and the routes as `v1alpha2` with
//! those fields optional.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
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

/// The types of one route kind, named as the `gateway-api` crate names them.
macro_rules! l4_route {
    (
        $kind:literal, $plural:literal, $route:literal, $spec:ident, $status_name:literal, $status:ident,
        $parent_ref:ident, $rule:ident, $backend_ref:ident, $status_parent:ident,
        $status_parent_ref:ident, { $($spec_field:tt)* }
    ) => {
        #[derive(CustomResource, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
        #[kube(
            group = "gateway.networking.k8s.io",
            version = "v1alpha2",
            kind = $kind,
            plural = $plural,
            root = $route,
            namespaced,
            status = $status_name,
            schema = "disabled",
            derive = "Default",
            derive = "PartialEq"
        )]
        pub struct $spec {
            $($spec_field)*
            #[serde(default, skip_serializing_if = "Option::is_none", rename = "parentRefs")]
            pub parent_refs: Option<Vec<$parent_ref>>,
            pub rules: Vec<$rule>,
        }

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
            #[serde(default, skip_serializing_if = "Option::is_none", rename = "sectionName")]
            pub section_name: Option<String>,
        }

        #[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
        pub struct $rule {
            #[serde(default, skip_serializing_if = "Option::is_none", rename = "backendRefs")]
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
            #[serde(default, skip_serializing_if = "Option::is_none", rename = "sectionName")]
            pub section_name: Option<String>,
        }
    };
}

l4_route!(
    "TLSRoute", "tlsroutes", "TlsRoute", TlsRouteSpec, "TlsRouteStatus", TlsRouteStatus, TlsRouteParentRefs,
    TlsRouteRules, TlsRouteRulesBackendRefs, TlsRouteStatusParents,
    TlsRouteStatusParentsParentRef, {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hostnames: Option<Vec<String>>,
    }
);

l4_route!(
    "TCPRoute",
    "tcproutes",
    "TcpRoute",
    TcpRouteSpec,
    "TcpRouteStatus",
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
    "UdpRoute",
    UdpRouteSpec,
    "UdpRouteStatus",
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
