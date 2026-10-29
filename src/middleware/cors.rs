use axum::body::Body;
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, VARY,
};
use axum::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};

use super::chain::{Flow, Middleware, RequestCtx};
use crate::model::CorsConfig;

/// How long a browser may cache a preflight answer when the route does not
/// say, as Gateway API's `maxAge` defaults.
const DEFAULT_MAX_AGE: u32 = 5;

/// Applies a route's CORS policy: answers the preflight requests of the
/// origins it allows, without reaching the backend, and marks the responses
/// to their other requests so the browser lets the page read them. A request
/// from any other origin goes on untouched, and gets no CORS header.
pub struct CorsMiddleware {
    config: CorsConfig,
    origins: Vec<AllowedOrigin>,
}

/// An entry of `allowOrigins`.
#[derive(Debug, PartialEq)]
enum AllowedOrigin {
    Any,
    /// `scheme://host[:port]`, the host lowercase; `wildcard` when it was
    /// `*.` followed by `host`, matching any name below `host`, or `*`
    /// alone, `host` then empty, matching any.
    Origin {
        scheme: String,
        host: String,
        port: Option<u16>,
        wildcard: bool,
    },
}

impl AllowedOrigin {
    fn parse(entry: &str) -> Option<Self> {
        if entry == "*" {
            return Some(Self::Any);
        }
        let (scheme, host, port) = split_origin(entry)?;
        if host == "*" {
            // Any host, on this scheme and port.
            return Some(Self::Origin {
                scheme,
                host: String::new(),
                port,
                wildcard: true,
            });
        }
        match host.strip_prefix("*.") {
            Some(base) if !base.is_empty() => Some(Self::Origin {
                scheme,
                host: base.to_string(),
                port,
                wildcard: true,
            }),
            Some(_) => None,
            None => Some(Self::Origin {
                scheme,
                host,
                port,
                wildcard: false,
            }),
        }
    }

    fn matches(&self, scheme: &str, host: &str, port: Option<u16>) -> bool {
        match self {
            Self::Any => true,
            Self::Origin {
                scheme: s,
                host: h,
                port: p,
                wildcard,
            } => {
                let host_matches = if *wildcard && h.is_empty() {
                    true
                } else if *wildcard {
                    host.strip_suffix(h.as_str())
                        .is_some_and(|label| label.len() > 1 && label.ends_with('.'))
                } else {
                    host == h
                };
                s == scheme
                    && host_matches
                    && p.or_else(|| default_port(s)) == port.or_else(|| default_port(scheme))
            }
        }
    }
}

/// An origin's scheme, lowercase host and port, `None` when it is not
/// `scheme://host[:port]`.
fn split_origin(origin: &str) -> Option<(String, String, Option<u16>)> {
    let (scheme, rest) = origin.split_once("://")?;
    if scheme.is_empty() || rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return None;
    }
    // An IPv6 address is bracketed: its colons are not the port's.
    let host_end = if rest.starts_with('[') {
        rest.find(']')? + 1
    } else {
        rest.rfind(':').unwrap_or(rest.len())
    };
    let (host, port) = rest.split_at(host_end);
    let port = match port.strip_prefix(':') {
        Some(port) => Some(port.parse::<u16>().ok()?),
        None if port.is_empty() => None,
        None => return None,
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme.to_ascii_lowercase(), host.to_ascii_lowercase(), port))
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

impl CorsMiddleware {
    pub fn new(config: &CorsConfig) -> Self {
        Self {
            origins: config
                .allow_origins
                .iter()
                .filter_map(|o| AllowedOrigin::parse(o.trim()))
                .collect(),
            config: config.clone(),
        }
    }

    /// Whether the policy lets `origin` read the route's responses.
    fn allows(&self, origin: &str) -> bool {
        // An opaque origin, a sandboxed page's, is `null`: only `*` takes it.
        if origin == "null" {
            return self.origins.contains(&AllowedOrigin::Any);
        }
        split_origin(origin).is_some_and(|(scheme, host, port)| {
            self.origins
                .iter()
                .any(|allowed| allowed.matches(&scheme, &host, port))
        })
    }

    /// `Access-Control-Allow-Origin` for `origin`: `*` when any origin may
    /// and no credentials go along, the origin itself otherwise.
    fn allow_origin<'a>(&self, origin: &'a str) -> &'a str {
        if !self.config.allow_credentials && self.origins.contains(&AllowedOrigin::Any) {
            "*"
        } else {
            origin
        }
    }

    /// Applies the policy to `headers`, those of the answer to a request
    /// from `origin`, whatever gave it, so the page can read an error too:
    /// the backend's own CORS headers give way to the policy's, which an
    /// origin it does not allow gets none of.
    pub fn mark_response(&self, origin: Option<&HeaderValue>, response: &mut Response<Body>) {
        // A preflight answer is the policy's own, complete already.
        if response.extensions().get::<Preflight>().is_some() {
            return;
        }
        let headers = response.headers_mut();
        for name in [
            ACCESS_CONTROL_ALLOW_ORIGIN,
            ACCESS_CONTROL_ALLOW_CREDENTIALS,
            ACCESS_CONTROL_ALLOW_METHODS,
            ACCESS_CONTROL_ALLOW_HEADERS,
            ACCESS_CONTROL_EXPOSE_HEADERS,
            ACCESS_CONTROL_MAX_AGE,
        ] {
            headers.remove(name);
        }
        // Before the marks, which may name the response's headers.
        vary_on_origin(headers);
        if let Some(origin) = origin
            .and_then(|o| o.to_str().ok())
            .filter(|o| self.allows(o))
        {
            self.mark(headers, origin);
        }
    }

    /// The headers every answer to an allowed `origin` carries.
    fn mark(&self, headers: &mut HeaderMap, origin: &str) {
        insert(
            headers,
            ACCESS_CONTROL_ALLOW_ORIGIN,
            self.allow_origin(origin),
        );
        if self.config.allow_credentials {
            insert(headers, ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        }
        if let Some(exposed) = self.exposed(headers) {
            insert(headers, ACCESS_CONTROL_EXPOSE_HEADERS, &exposed);
        }
    }

    /// `Access-Control-Expose-Headers` for a response carrying `headers`. A
    /// `*` names them all when credentials go along, browsers reading `*`
    /// literally then.
    fn exposed(&self, headers: &HeaderMap) -> Option<String> {
        let exposed = &self.config.expose_headers;
        if exposed.is_empty() {
            return None;
        }
        if !(self.config.allow_credentials && exposed.iter().any(|h| h == "*")) {
            return Some(exposed.join(", "));
        }
        let mut names: Vec<&str> = exposed
            .iter()
            .map(String::as_str)
            .filter(|h| *h != "*")
            .chain(headers.keys().map(|name| name.as_str()))
            .collect();
        names.sort_unstable();
        names.dedup();
        (!names.is_empty()).then(|| names.join(", "))
    }

    /// The answer to a preflight request from an allowed `origin`. A `*`
    /// list echoes what the request asks for when credentials go along,
    /// browsers reading `*` literally then.
    fn preflight(&self, origin: &str, request: &HeaderMap) -> Response<Body> {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        response.extensions_mut().insert(Preflight);
        let headers = response.headers_mut();
        self.mark(headers, origin);
        vary_on_preflight(headers);
        let listed = |list: &[String], asked: Option<&HeaderValue>| {
            if list.iter().any(|v| v == "*") {
                if self.config.allow_credentials {
                    asked.and_then(|v| v.to_str().ok()).map(str::to_string)
                } else {
                    Some("*".to_string())
                }
            } else if list.is_empty() {
                None
            } else {
                Some(list.join(", "))
            }
        };
        if let Some(methods) = listed(
            &self.config.allow_methods,
            request.get(ACCESS_CONTROL_REQUEST_METHOD),
        ) {
            insert(headers, ACCESS_CONTROL_ALLOW_METHODS, &methods);
        }
        let asked_headers = request.get(ACCESS_CONTROL_REQUEST_HEADERS);
        if let Some(mut allowed) = listed(&self.config.allow_headers, asked_headers) {
            // `*` never covers `Authorization`: browsers want it named.
            let asks_authorization = asked_headers
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| {
                    v.split(',')
                        .any(|h| h.trim().eq_ignore_ascii_case("authorization"))
                });
            if allowed == "*" && asks_authorization {
                allowed.push_str(", authorization");
            }
            insert(headers, ACCESS_CONTROL_ALLOW_HEADERS, &allowed);
        }
        let max_age = self.config.max_age.unwrap_or(DEFAULT_MAX_AGE);
        insert(headers, ACCESS_CONTROL_MAX_AGE, &max_age.to_string());
        response
    }

    /// The answer to a preflight request from an origin the policy does not
    /// allow: no CORS header, so the browser refuses the request it asks
    /// about.
    fn refused_preflight() -> Response<Body> {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        response.extensions_mut().insert(Preflight);
        vary_on_preflight(response.headers_mut());
        response
    }
}

/// A preflight answer depends on the method and headers asked for too.
fn vary_on_preflight(headers: &mut HeaderMap) {
    vary_on_origin(headers);
    headers.append(
        VARY,
        HeaderValue::from_static("Access-Control-Request-Method, Access-Control-Request-Headers"),
    );
}

/// Marks the answer to a preflight request, which the policy gave itself.
#[derive(Clone, Copy)]
struct Preflight;

/// The answer depends on the request's origin, whether it got CORS headers
/// or not: a cache must not serve it to another.
fn vary_on_origin(headers: &mut HeaderMap) {
    let varies = headers
        .get_all(VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|v| v.trim().eq_ignore_ascii_case("origin") || v.trim() == "*");
    if !varies {
        headers.append(VARY, HeaderValue::from_static("Origin"));
    }
}

fn insert(headers: &mut HeaderMap, name: axum::http::HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

#[async_trait::async_trait]
impl Middleware for CorsMiddleware {
    fn name(&self) -> &'static str {
        "cors"
    }

    async fn on_request(&self, _ctx: &mut RequestCtx, req: &mut Request<Body>) -> Flow {
        let headers = req.headers();
        let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) else {
            return Flow::Continue;
        };
        // A preflight is the policy's to answer, whatever its origin: the
        // backend never sees it.
        if req.method() == Method::OPTIONS && headers.contains_key(ACCESS_CONTROL_REQUEST_METHOD) {
            return Flow::ShortCircuit(if self.allows(origin) {
                self.preflight(origin, headers)
            } else {
                Self::refused_preflight()
            });
        }
        // Other requests' responses are marked once answered: see
        // `mark_response`.
        Flow::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> RequestCtx {
        RequestCtx {
            host: "example.com".to_string(),
            client_addr: None,
            is_tls: false,
            method: Method::GET,
            path: "/".to_string(),
            client_encoding: None,
            pending_response_headers: Vec::new(),
            in_flight_guards: Vec::new(),
        }
    }

    fn policy() -> CorsConfig {
        CorsConfig {
            allow_origins: vec!["https://www.foo.com".into(), "https://*.bar.com".into()],
            allow_methods: vec!["GET".into(), "OPTIONS".into()],
            allow_headers: vec!["x-header-1".into(), "x-header-2".into()],
            expose_headers: vec!["x-header-3".into(), "x-header-4".into()],
            allow_credentials: true,
            max_age: Some(3600),
        }
    }

    fn request(method: Method, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri("/");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).unwrap()
    }

    async fn preflight(cors: &CorsMiddleware, headers: &[(&str, &str)]) -> Option<Response<Body>> {
        let mut req = request(Method::OPTIONS, headers);
        match cors.on_request(&mut ctx(), &mut req).await {
            Flow::ShortCircuit(resp) => Some(resp),
            Flow::Continue => None,
        }
    }

    /// `headers` once marked by `cors`, as a response to `origin`.
    fn mark(cors: &CorsMiddleware, origin: Option<&HeaderValue>, headers: &mut HeaderMap) {
        let mut response = Response::new(Body::empty());
        *response.headers_mut() = std::mem::take(headers);
        cors.mark_response(origin, &mut response);
        *headers = std::mem::take(response.headers_mut());
    }

    fn header<'a>(resp: &'a Response<Body>, name: &str) -> Option<&'a str> {
        resp.headers().get(name).and_then(|v| v.to_str().ok())
    }

    #[test]
    fn origins_match_exactly_or_below_a_wildcard() {
        let cors = CorsMiddleware::new(&policy());
        assert!(cors.allows("https://www.foo.com"));
        assert!(cors.allows("HTTPS://WWW.FOO.COM"));
        assert!(cors.allows("https://www.foo.com:443"));
        assert!(cors.allows("https://www.bar.com"));
        assert!(cors.allows("https://xpto.www.bar.com"));
        assert!(!cors.allows("https://bar.com"));
        assert!(!cors.allows("https://foobar.com"));
        assert!(!cors.allows("http://www.foo.com"));
        assert!(!cors.allows("https://www.foo.com:8443"));
        assert!(!cors.allows("null"));
        let any = CorsMiddleware::new(&CorsConfig {
            allow_origins: vec!["*".into()],
            ..Default::default()
        });
        assert!(any.allows("https://foobar.com:12345"));
        // An opaque origin only `*` allows.
        assert!(any.allows("null"));
        assert!(!CorsMiddleware::new(&policy()).allows("null"));
    }

    #[tokio::test]
    async fn a_preflight_from_an_allowed_origin_is_answered() {
        let cors = CorsMiddleware::new(&policy());
        let resp = preflight(
            &cors,
            &[
                ("origin", "https://www.foo.com"),
                ("access-control-request-method", "GET"),
                ("access-control-request-headers", "x-header-1"),
            ],
        )
        .await
        .expect("the preflight went to the backend");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            header(&resp, "access-control-allow-origin"),
            Some("https://www.foo.com")
        );
        assert_eq!(
            header(&resp, "access-control-allow-methods"),
            Some("GET, OPTIONS")
        );
        assert_eq!(
            header(&resp, "access-control-allow-headers"),
            Some("x-header-1, x-header-2")
        );
        assert_eq!(
            header(&resp, "access-control-expose-headers"),
            Some("x-header-3, x-header-4")
        );
        assert_eq!(header(&resp, "access-control-max-age"), Some("3600"));
        assert_eq!(
            header(&resp, "access-control-allow-credentials"),
            Some("true")
        );
        assert_eq!(header(&resp, "vary"), Some("Origin"));
        assert_eq!(resp.headers().get_all("vary").iter().count(), 2);
        // Marked on its way out like any other answer, it keeps them all.
        let mut resp = resp;
        let origin = HeaderValue::from_static("https://www.foo.com");
        cors.mark_response(Some(&origin), &mut resp);
        assert_eq!(header(&resp, "access-control-max-age"), Some("3600"));
        assert_eq!(
            header(&resp, "access-control-allow-methods"),
            Some("GET, OPTIONS")
        );
    }

    #[tokio::test]
    async fn a_preflight_from_another_origin_is_refused() {
        let cors = CorsMiddleware::new(&policy());
        let resp = preflight(
            &cors,
            &[
                ("origin", "https://foobar.com"),
                ("access-control-request-method", "GET"),
            ],
        )
        .await
        .expect("the preflight went to the backend");
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(header(&resp, "access-control-allow-origin"), None);
        // An OPTIONS request asking for no method is no preflight.
        assert!(
            preflight(&cors, &[("origin", "https://www.foo.com")])
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn wildcards_echo_the_request_only_with_credentials() {
        let wildcards = |allow_credentials| {
            CorsMiddleware::new(&CorsConfig {
                allow_origins: vec!["*".into()],
                allow_methods: vec!["*".into()],
                allow_headers: vec!["*".into()],
                allow_credentials,
                ..Default::default()
            })
        };
        let asked = [
            ("origin", "https://other.foo.com"),
            ("access-control-request-method", "PUT"),
            ("access-control-request-headers", "x-header-1, x-header-2"),
        ];
        let resp = preflight(&wildcards(true), &asked).await.unwrap();
        assert_eq!(
            header(&resp, "access-control-allow-origin"),
            Some("https://other.foo.com")
        );
        assert_eq!(header(&resp, "access-control-allow-methods"), Some("PUT"));
        assert_eq!(
            header(&resp, "access-control-allow-headers"),
            Some("x-header-1, x-header-2")
        );
        assert_eq!(
            header(&resp, "access-control-allow-credentials"),
            Some("true")
        );
        let resp = preflight(&wildcards(false), &asked).await.unwrap();
        assert_eq!(header(&resp, "access-control-allow-origin"), Some("*"));
        assert_eq!(header(&resp, "access-control-allow-methods"), Some("*"));
        assert_eq!(header(&resp, "access-control-allow-headers"), Some("*"));
        assert_eq!(header(&resp, "access-control-allow-credentials"), None);
        assert_eq!(header(&resp, "access-control-max-age"), Some("5"));
        // `*` does not cover `Authorization`.
        let resp = preflight(
            &wildcards(false),
            &[
                ("origin", "https://other.foo.com"),
                ("access-control-request-method", "GET"),
                ("access-control-request-headers", "Authorization"),
            ],
        )
        .await
        .unwrap();
        assert_eq!(
            header(&resp, "access-control-allow-headers"),
            Some("*, authorization")
        );
    }

    #[tokio::test]
    async fn the_response_to_an_allowed_origin_is_marked() {
        let cors = CorsMiddleware::new(&policy());
        let mut req = request(Method::GET, &[("origin", "https://www.bar.com")]);
        assert!(matches!(
            cors.on_request(&mut ctx(), &mut req).await,
            Flow::Continue
        ));
        let origin = |o: &'static str| HeaderValue::from_static(o);
        let mut headers = HeaderMap::new();
        mark(&cors, Some(&origin("https://www.bar.com")), &mut headers);
        assert_eq!(
            headers["access-control-allow-origin"],
            "https://www.bar.com"
        );
        assert_eq!(headers["access-control-allow-credentials"], "true");
        assert_eq!(
            headers["access-control-expose-headers"],
            "x-header-3, x-header-4"
        );
        // Marked twice, the response still varies on the origin once.
        mark(&cors, Some(&origin("https://www.bar.com")), &mut headers);
        assert_eq!(headers.get_all("vary").iter().count(), 1);
        // Another origin's response carries no CORS header, the backend's
        // own included, and varies on the origin all the same.
        let mut headers = HeaderMap::new();
        headers.insert("access-control-allow-origin", origin("*"));
        headers.insert("access-control-allow-credentials", origin("true"));
        mark(&cors, Some(&origin("https://foobar.com")), &mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers["vary"], "Origin");
        let mut headers = HeaderMap::new();
        mark(&cors, None, &mut headers);
        assert_eq!(headers["vary"], "Origin");
    }

    #[test]
    fn a_wildcard_host_keeps_its_scheme_and_port() {
        let cors = CorsMiddleware::new(&CorsConfig {
            allow_origins: vec!["https://*".into()],
            ..Default::default()
        });
        assert!(cors.allows("https://anything.example"));
        assert!(cors.allows("https://example.com:443"));
        assert!(!cors.allows("http://anything.example"));
        assert!(!cors.allows("https://example.com:8443"));
    }

    #[test]
    fn a_wildcard_exposes_the_response_headers_with_credentials() {
        let exposing = |allow_credentials| {
            CorsMiddleware::new(&CorsConfig {
                allow_origins: vec!["https://app.example".into()],
                expose_headers: vec!["*".into()],
                allow_credentials,
                ..Default::default()
            })
        };
        let response = || {
            let mut headers = HeaderMap::new();
            headers.insert("x-total-count", HeaderValue::from_static("3"));
            headers.insert("content-type", HeaderValue::from_static("text/plain"));
            headers
        };
        let origin = HeaderValue::from_static("https://app.example");
        let mut headers = response();
        mark(&exposing(false), Some(&origin), &mut headers);
        assert_eq!(headers["access-control-expose-headers"], "*");
        let mut headers = response();
        mark(&exposing(true), Some(&origin), &mut headers);
        assert_eq!(
            headers["access-control-expose-headers"],
            "access-control-allow-credentials, access-control-allow-origin, content-type, vary, \
             x-total-count"
        );
    }
}
