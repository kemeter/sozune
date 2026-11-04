//! Translation of a Gateway API `GRPCRoute` into the `HTTPRoute` it routes
//! like, so it goes through the HTTPRoute pipeline (scope, hostnames,
//! backendRefs, filters, status) unchanged.
//!
//! A gRPC call is an HTTP/2 `POST` to `/<service>/<method>`, so a method
//! match is a path match:
//!
//! - `service` and `method` → the exact path `/<service>/<method>`;
//! - `service` alone → the prefix `/<service>/`;
//! - `method` alone → the path regex `/[^/]+/<method>`;
//! - `type: RegularExpression` → the path regex built from both, a missing
//!   one standing for any name.
//!
//! Header matches, filters and backendRefs have the same shape in both
//! kinds and are carried over as they are. Every match, a rule without any
//! included, also requires a `POST` with a gRPC `content-type`
//! ([`GRPC_CONTENT_TYPE`]): a GRPCRoute routes gRPC calls, not every request
//! on its hostnames.
//!
//! The translated route keeps the GRPCRoute's namespace and uid, and takes
//! its name behind [`GRPC_NAME_PREFIX`]: Kubernetes names cannot hold a `/`,
//! so its entrypoints never collide with those of an HTTPRoute of the same
//! name, and [`route_kind`] tells it apart.

use gateway_api::apis::standard::grpcroutes::GrpcRoute;
use gateway_api::apis::standard::httproutes::HttpRoute;
use serde_json::{Map, Value, json};

/// Put before the name of the HTTPRoute a GRPCRoute is translated into.
pub const GRPC_NAME_PREFIX: &str = "grpc/";

/// The `content-type` of a gRPC call: `application/grpc`, maybe with a
/// `+<format>` suffix or parameters.
pub const GRPC_CONTENT_TYPE: &str = "application/grpc([+;].*)?";

/// The Gateway API kind of a route handled by the HTTPRoute pipeline:
/// `GRPCRoute` for one translated by [`to_http_route`], `HTTPRoute`
/// otherwise.
pub fn route_kind(route: &HttpRoute) -> &'static str {
    if route
        .metadata
        .name
        .as_deref()
        .is_some_and(|name| name.starts_with(GRPC_NAME_PREFIX))
    {
        "GRPCRoute"
    } else {
        "HTTPRoute"
    }
}

/// The name of the GRPCRoute `route` was translated from, or its own.
pub fn source_name(route: &HttpRoute) -> Option<&str> {
    let name = route.metadata.name.as_deref()?;
    Some(name.strip_prefix(GRPC_NAME_PREFIX).unwrap_or(name))
}

/// The HTTPRoute `route` routes like. `None` when the GRPCRoute cannot be
/// read back as one, which its schema rules out.
pub fn to_http_route(route: &GrpcRoute) -> Option<HttpRoute> {
    let mut value = serde_json::to_value(route).ok()?;
    let object = value.as_object_mut()?;
    object.insert("kind".into(), json!("HTTPRoute"));
    let metadata = object.get_mut("metadata")?.as_object_mut()?;
    let name = metadata.get("name")?.as_str()?.to_string();
    metadata.insert("name".into(), json!(format!("{GRPC_NAME_PREFIX}{name}")));
    if let Some(rules) = object
        .get_mut("spec")
        .and_then(|spec| spec.get_mut("rules"))
        .and_then(Value::as_array_mut)
    {
        for rule in rules {
            let Some(rule) = rule.as_object_mut() else {
                continue;
            };
            let matches = rule.entry("matches").or_insert_with(|| json!([]));
            if !matches.is_array() {
                *matches = json!([]);
            }
            let Some(matches) = matches.as_array_mut() else {
                continue;
            };
            if matches.is_empty() {
                matches.push(json!({}));
            }
            for m in matches {
                translate_match(m);
            }
        }
    }
    serde_json::from_value(value).ok()
}

/// A GRPCRoute match, rewritten in place as the HTTPRoute match it is.
fn translate_match(m: &mut Value) {
    let Some(object) = m.as_object_mut() else {
        return;
    };
    let method = object.remove("method");
    if let Some(path) = method.as_ref().and_then(method_path) {
        object.insert("path".into(), path);
    }
    let headers = object.entry("headers").or_insert_with(|| json!([]));
    if !headers.is_array() {
        *headers = json!([]);
    }
    if let Some(headers) = headers.as_array_mut() {
        // A name listed again, whatever its case, is ignored: only the first
        // value counts.
        let mut seen = std::collections::HashSet::new();
        headers.retain(|header| {
            header
                .get("name")
                .and_then(Value::as_str)
                .is_none_or(|name| seen.insert(name.to_ascii_lowercase()))
        });
        for header in headers.iter_mut() {
            if let Some(header) = header.as_object_mut()
                && !header.contains_key("type")
            {
                header.insert("type".into(), json!("Exact"));
            }
        }
        headers.push(json!({
            "name": "content-type",
            "type": "RegularExpression",
            "value": GRPC_CONTENT_TYPE,
        }));
    }
    object.insert("method".into(), json!("POST"));
}

/// The HTTPRoute path match of a GRPCRoute method match, `None` when it
/// names neither a service nor a method.
fn method_path(method: &Value) -> Option<Value> {
    let method = method.as_object()?;
    let field = |key: &str| {
        method
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    };
    let service = field("service");
    let name = field("method");
    let regex = method.get("type").and_then(Value::as_str) == Some("RegularExpression");
    let path = |kind: &str, value: String| {
        let mut path = Map::new();
        path.insert("type".into(), json!(kind));
        path.insert("value".into(), json!(value));
        Value::Object(path)
    };
    match (service, name, regex) {
        (None, None, _) => None,
        (service, name, true) => Some(path(
            "RegularExpression",
            format!(
                "/(?:{})/(?:{})",
                service.unwrap_or("[^/]+"),
                name.unwrap_or("[^/]+")
            ),
        )),
        (Some(service), Some(name), false) => Some(path("Exact", format!("/{service}/{name}"))),
        (Some(service), None, false) => Some(path("PathPrefix", format!("/{service}/"))),
        (None, Some(name), false) => Some(path(
            "RegularExpression",
            format!("/[^/]+/{}", regex::escape(name)),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_api::apis::standard::httproutes::{
        HttpRouteRulesMatches, HttpRouteRulesMatchesHeadersType, HttpRouteRulesMatchesMethod,
        HttpRouteRulesMatchesPathType,
    };

    fn grpc_route(matches: Value) -> GrpcRoute {
        serde_json::from_value(json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "echo", "namespace": "ns", "uid": "u1" },
            "spec": {
                "parentRefs": [{ "name": "gw" }],
                "hostnames": ["grpc.example.com"],
                "rules": [{
                    "matches": matches,
                    "filters": [{
                        "type": "RequestHeaderModifier",
                        "requestHeaderModifier": { "set": [{ "name": "x-a", "value": "1" }] }
                    }],
                    "backendRefs": [{ "name": "echo", "port": 8080, "weight": 2 }]
                }]
            }
        }))
        .unwrap()
    }

    fn path_of(route: &HttpRoute) -> (Option<HttpRouteRulesMatchesPathType>, Option<String>) {
        let rules = route.spec.rules.as_ref().unwrap();
        let path = rules[0].matches.as_ref().unwrap()[0].path.clone().unwrap();
        (path.r#type, path.value)
    }

    #[test]
    fn service_and_method_become_an_exact_path() {
        let route = to_http_route(&grpc_route(
            json!([{ "method": { "service": "pkg.Echo", "method": "Ping" } }]),
        ))
        .unwrap();
        assert_eq!(
            path_of(&route),
            (
                Some(HttpRouteRulesMatchesPathType::Exact),
                Some("/pkg.Echo/Ping".into())
            )
        );
    }

    #[test]
    fn a_service_alone_becomes_a_prefix() {
        let route = to_http_route(&grpc_route(
            json!([{ "method": { "service": "pkg.Echo" } }]),
        ))
        .unwrap();
        assert_eq!(
            path_of(&route),
            (
                Some(HttpRouteRulesMatchesPathType::PathPrefix),
                Some("/pkg.Echo/".into())
            )
        );
    }

    #[test]
    fn a_method_alone_becomes_a_path_regex() {
        let route =
            to_http_route(&grpc_route(json!([{ "method": { "method": "Ping.v2" } }]))).unwrap();
        assert_eq!(
            path_of(&route),
            (
                Some(HttpRouteRulesMatchesPathType::RegularExpression),
                Some(r"/[^/]+/Ping\.v2".into())
            )
        );
    }

    #[test]
    fn a_regular_expression_method_match_becomes_a_path_regex() {
        let route = to_http_route(&grpc_route(json!([{
            "method": { "type": "RegularExpression", "service": "pkg\\..*", "method": "Get|List" }
        }])))
        .unwrap();
        assert_eq!(
            path_of(&route),
            (
                Some(HttpRouteRulesMatchesPathType::RegularExpression),
                Some(r"/(?:pkg\..*)/(?:Get|List)".into())
            )
        );
        let route = to_http_route(&grpc_route(
            json!([{ "method": { "type": "RegularExpression", "method": "Get" } }]),
        ))
        .unwrap();
        assert_eq!(path_of(&route).1.as_deref(), Some("/(?:[^/]+)/(?:Get)"));
    }

    #[test]
    fn header_matches_filters_and_backend_refs_are_kept() {
        let route = to_http_route(&grpc_route(json!([{
            "headers": [{ "name": "version", "value": "two" }]
        }])))
        .unwrap();
        let rule = &route.spec.rules.as_ref().unwrap()[0];
        let m = &rule.matches.as_ref().unwrap()[0];
        assert!(m.path.is_none());
        let headers = m.headers.as_ref().unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].name, "version");
        assert_eq!(headers[0].value, "two");
        assert_eq!(
            headers[0].r#type,
            Some(HttpRouteRulesMatchesHeadersType::Exact)
        );
        assert_eq!(rule.filters.as_ref().unwrap().len(), 1);
        let backend = &rule.backend_refs.as_ref().unwrap()[0];
        assert_eq!(
            (backend.name.as_str(), backend.port, backend.weight),
            ("echo", Some(8080), Some(2))
        );
        assert_eq!(
            route.spec.hostnames.as_deref(),
            Some(&["grpc.example.com".to_string()][..])
        );
    }

    #[test]
    fn a_header_listed_again_is_ignored() {
        let route = to_http_route(&grpc_route(json!([{
            "headers": [
                { "name": "version", "value": "one" },
                { "name": "Version", "value": "two" },
                { "name": "color", "value": "blue" }
            ]
        }])))
        .unwrap();
        let m = &route.spec.rules.as_ref().unwrap()[0]
            .matches
            .as_ref()
            .unwrap()[0];
        let headers: Vec<(&str, &str)> = m
            .headers
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|h| (h.name.as_str(), h.value.as_str()))
            .collect();
        assert_eq!(
            headers,
            [
                ("version", "one"),
                ("color", "blue"),
                ("content-type", GRPC_CONTENT_TYPE)
            ]
        );
    }

    /// Only gRPC calls are routed, a rule without matches included.
    #[test]
    fn every_match_requires_a_grpc_content_type() {
        let content_type = |m: &HttpRouteRulesMatches| {
            m.headers.as_deref().unwrap_or_default().iter().any(|h| {
                h.name == "content-type"
                    && h.value == GRPC_CONTENT_TYPE
                    && h.r#type == Some(HttpRouteRulesMatchesHeadersType::RegularExpression)
            })
        };
        let route = to_http_route(&grpc_route(json!([
            { "method": { "service": "pkg.Echo" } },
            { "headers": [{ "name": "version", "value": "two" }] }
        ])))
        .unwrap();
        let matches = route.spec.rules.as_ref().unwrap()[0]
            .matches
            .clone()
            .unwrap();
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(content_type));
        assert!(
            matches
                .iter()
                .all(|m| m.method == Some(HttpRouteRulesMatchesMethod::Post))
        );

        let route = to_http_route(&grpc_route(Value::Null)).unwrap();
        let matches = route.spec.rules.as_ref().unwrap()[0]
            .matches
            .clone()
            .unwrap();
        assert_eq!(matches.len(), 1);
        assert!(matches[0].path.is_none());
        assert!(content_type(&matches[0]));

        let regex = regex::Regex::new(&format!("^(?:{GRPC_CONTENT_TYPE})$")).unwrap();
        for ok in [
            "application/grpc",
            "application/grpc+proto",
            "application/grpc;charset=utf-8",
        ] {
            assert!(regex.is_match(ok), "{ok}");
        }
        for no in ["application/json", "application/grpc-web", "text/html"] {
            assert!(!regex.is_match(no), "{no}");
        }
    }

    #[test]
    fn the_translated_route_is_told_apart_by_its_name() {
        let route = to_http_route(&grpc_route(json!([]))).unwrap();
        assert_eq!(route.metadata.name.as_deref(), Some("grpc/echo"));
        assert_eq!(route.metadata.namespace.as_deref(), Some("ns"));
        assert_eq!(route.metadata.uid.as_deref(), Some("u1"));
        assert_eq!(route_kind(&route), "GRPCRoute");
        assert_eq!(source_name(&route), Some("echo"));
        let mut plain = route.clone();
        plain.metadata.name = Some("echo".into());
        assert_eq!(route_kind(&plain), "HTTPRoute");
        assert_eq!(source_name(&plain), Some("echo"));
    }
}
