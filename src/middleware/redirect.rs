use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use regex::Regex;
use sozu_lib::router::DomainRule;

use super::chain::{Flow, Middleware, RequestCtx};
use crate::model::{EntrypointConfig, RedirectScheme};

/// Answers every request of a route with a redirect Sōzu has no status for
/// (`303`, `307`). Its `Location` is built as Sōzu builds its own: the
/// route's scheme, host, port and path, each falling back on the request's,
/// the host and path templates taking the captures of the route's rules.
pub struct RedirectMiddleware {
    status: StatusCode,
    scheme: Option<RedirectScheme>,
    host: Option<String>,
    port: Option<u16>,
    /// The port of the HTTPS listener, for a redirect to HTTPS.
    https_port: Option<u16>,
    path: Option<String>,
    /// Whether the request's query follows `path`: a redirect's own path
    /// with no query of its own replaces the path alone.
    keeps_query: bool,
    /// The route's `redirect_template`: a whole response when it starts with
    /// a status line, as Sōzu reads it, the `Location` otherwise.
    /// `%REDIRECT_LOCATION` and `%STATUS_CODE` are filled in.
    template: Option<String>,
    hostnames: Vec<DomainRule>,
    path_rule: PathCaptures,
}

/// How the route's path rule captures parts of the path, numbered as Sōzu
/// numbers them: the whole path first.
enum PathCaptures {
    /// The path alone, as for an exact rule.
    Whole,
    Prefix(String),
    Regex(Regex),
}

impl RedirectMiddleware {
    /// The redirect of a route, `None` when Sōzu answers it. `path_rule` and
    /// `rewrite` are the rule and rewrite template its frontends carry.
    pub fn new(
        config: &EntrypointConfig,
        path_rule: &sozu_command_lib::proto::command::PathRule,
        rewrite: Option<String>,
    ) -> Option<Self> {
        let status = config.middleware_redirect_status()?;
        let path_rule = match path_rule.kind {
            0 => PathCaptures::Prefix(path_rule.value.clone()),
            1 => match Regex::new(&format!("^(?:{})$", path_rule.value)) {
                Ok(regex) => PathCaptures::Regex(regex),
                Err(_) => PathCaptures::Whole,
            },
            _ => PathCaptures::Whole,
        };
        Some(Self {
            status: StatusCode::from_u16(status).ok()?,
            scheme: config.redirect_scheme,
            host: config.rewrite_host.clone(),
            port: config.rewrite_port,
            https_port: config.https_redirect_port,
            // A redirect's own path wins over the route's rewrite, as on
            // Sōzu's frontends.
            path: config.rewrite_path.clone().or(rewrite),
            keeps_query: config
                .rewrite_path
                .as_deref()
                .is_some_and(crate::model::fixed_redirect_path),
            template: config
                .redirect_template
                .clone()
                .filter(|template| !template.is_empty()),
            hostnames: config
                .hostnames
                .iter()
                .filter_map(|h| h.parse().ok())
                .collect(),
            path_rule,
        })
    }

    fn location(&self, is_tls: bool, authority: &str, path: &str) -> String {
        let scheme = match self.scheme {
            Some(RedirectScheme::UseHttps) => "https",
            Some(RedirectScheme::UseHttp) => "http",
            Some(RedirectScheme::UseSame) | None if is_tls => "https",
            Some(RedirectScheme::UseSame) | None => "http",
        };
        let request_host = strip_port(authority).to_ascii_lowercase();
        let host_captures = self.host_captures(&request_host);
        let path_captures = self.path_captures(path);
        let expand = |template: &str| expand(template, &host_captures, &path_captures);
        let host = match &self.host {
            Some(template) => expand(template),
            None => request_host.clone(),
        };
        let host = strip_port(&host);
        // The HTTPS listener's port, Sōzu's fallback, only fits HTTPS.
        let port = self.port.or(self.https_port.filter(|_| scheme == "https"));
        let port = match (port, scheme) {
            (Some(80), "http") | (Some(443), "https") | (None, _) => String::new(),
            (Some(port), _) => format!(":{port}"),
        };
        let query = path.find('?').map_or("", |start| &path[start..]);
        let path = match &self.path {
            Some(template) if self.keeps_query => format!("{}{query}", expand(template)),
            Some(template) => expand(template),
            None => path.to_string(),
        };
        format!("{scheme}://{host}{port}{path}")
    }

    /// The redirect to `location`, as the route's template makes it.
    /// `route` and `request_id` fill `%ROUTE` and `%REQUEST_ID`, as Sōzu
    /// fills them.
    fn respond(&self, location: &str, route: &str, request_id: &str) -> Response<Body> {
        let fill = |template: &str| {
            template
                .replace("%REDIRECT_LOCATION", location)
                .replace("%STATUS_CODE", self.status.as_str())
                .replace("%ROUTE", route)
                .replace("%REQUEST_ID", request_id)
        };
        let mut response = Response::new(Body::empty());
        *response.status_mut() = self.status;
        let location = match &self.template {
            Some(template) if template.trim_start().starts_with("HTTP/") => {
                // Its status line gives way to the route's status, and the
                // length is counted again.
                let filled = fill(template.trim_start()).replace("\r\n", "\n");
                let (head, body) = filled.split_once("\n\n").unwrap_or((&filled, ""));
                for line in head.lines().skip(1) {
                    let Some((name, value)) = line.split_once(':') else {
                        continue;
                    };
                    let (Ok(name), Ok(value)) = (
                        header::HeaderName::try_from(name.trim()),
                        header::HeaderValue::try_from(value.trim()),
                    ) else {
                        continue;
                    };
                    if name != header::CONTENT_LENGTH {
                        response.headers_mut().append(name, value);
                    }
                }
                *response.body_mut() = Body::from(body.to_string());
                return response;
            }
            Some(template) => fill(template),
            None => location.to_string(),
        };
        match location.parse() {
            Ok(value) => {
                response.headers_mut().insert(header::LOCATION, value);
            }
            Err(_) => {
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            }
        }
        response
    }

    /// The captures of the first hostname of the route `host` matches: the
    /// host, then what a wildcard covers or the groups of a regex.
    fn host_captures<'a>(&self, host: &'a str) -> Vec<&'a str> {
        let mut captures = vec![host];
        match self
            .hostnames
            .iter()
            .find(|rule| rule.matches(host.as_bytes()))
        {
            Some(DomainRule::Wildcard(suffix)) => {
                let head = host.len().saturating_sub(suffix.len().saturating_sub(1));
                captures.push(&host[..head]);
            }
            Some(DomainRule::Regex(regex)) => {
                if let Some(caps) = regex.captures(host.as_bytes()) {
                    captures.extend(caps.iter().skip(1).map(|c| {
                        c.and_then(|m| std::str::from_utf8(m.as_bytes()).ok())
                            .unwrap_or("")
                    }));
                }
            }
            _ => {}
        }
        captures
    }

    fn path_captures<'a>(&self, path: &'a str) -> Vec<&'a str> {
        let mut captures = vec![path];
        match &self.path_rule {
            PathCaptures::Whole => {}
            PathCaptures::Prefix(prefix) => captures.push(&path[prefix.len().min(path.len())..]),
            PathCaptures::Regex(regex) => {
                if let Some(caps) = regex.captures(path) {
                    captures.extend(
                        caps.iter()
                            .skip(1)
                            .map(|c| c.map(|m| m.as_str()).unwrap_or("")),
                    );
                }
            }
        }
        captures
    }
}

/// `authority` without its `:port`, a bracketed IPv6 address kept whole.
fn strip_port(authority: &str) -> &str {
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    }
}

/// `template` with each `$HOST[n]` and `$PATH[n]` replaced by the `n`th
/// capture of the host or the path, empty when there is none.
fn expand(template: &str, host: &[&str], path: &[&str]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('$') {
        out.push_str(&rest[..start]);
        let token = &rest[start..];
        let parsed =
            [("$HOST[", host), ("$PATH[", path)]
                .into_iter()
                .find_map(|(prefix, captures)| {
                    let (index, tail) = token.strip_prefix(prefix)?.split_once(']')?;
                    let index: usize = index.parse().ok()?;
                    Some((captures.get(index).copied().unwrap_or(""), tail))
                });
        match parsed {
            Some((value, tail)) => {
                out.push_str(value);
                rest = tail;
            }
            None => {
                out.push('$');
                rest = &token[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[async_trait::async_trait]
impl Middleware for RedirectMiddleware {
    fn name(&self) -> &'static str {
        "redirect"
    }

    async fn on_request(&self, ctx: &mut RequestCtx, req: &mut Request<Body>) -> Flow {
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        // The listener's scheme, as its frontend names it.
        let is_tls = req
            .headers()
            .get(super::SCHEME_HEADER)
            .map_or(ctx.is_tls, |scheme| scheme == "https");
        let location = self.location(is_tls, &ctx.host, path);
        let route = format!("{} {}{}", req.method(), ctx.host, path);
        // The correlation id Sōzu gives the request.
        let request_id = req
            .headers()
            .get("sozu-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        Flow::ShortCircuit(self.respond(&location, &route, request_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PathConfig, PathRewrite, PathRuleType, RedirectPolicy, UrlRewrite};
    use sozu_command_lib::proto::command::PathRule;

    fn middleware(
        config: &EntrypointConfig,
        rule: PathRule,
        rewrite: Option<&str>,
    ) -> RedirectMiddleware {
        RedirectMiddleware::new(config, &rule, rewrite.map(String::from)).expect("a redirect")
    }

    fn see_other() -> EntrypointConfig {
        EntrypointConfig {
            redirect: Some(RedirectPolicy::SeeOther),
            ..Default::default()
        }
    }

    fn prefix(value: &str) -> PathRule {
        PathRule {
            value: value.to_string(),
            kind: 0,
        }
    }

    #[test]
    fn sozu_answers_its_own_redirects() {
        let config = EntrypointConfig {
            redirect: Some(RedirectPolicy::PermanentRedirect),
            ..Default::default()
        };
        assert!(RedirectMiddleware::new(&config, &prefix("/"), None).is_none());
    }

    /// To a fixed path, Sōzu would send the `Location` without the request's
    /// query: the middleware answers such a redirect, whatever its status.
    #[test]
    fn a_redirect_to_a_fixed_path_keeps_the_query_whatever_its_status() {
        for (policy, status) in [
            (RedirectPolicy::Permanent, 301),
            (RedirectPolicy::Found, 302),
            (RedirectPolicy::PermanentRedirect, 308),
        ] {
            let config = EntrypointConfig {
                redirect: Some(policy),
                rewrite_path: Some("/new".to_string()),
                ..Default::default()
            };
            assert_eq!(config.middleware_redirect_status(), Some(status));
            let m = middleware(&config, prefix("/"), None);
            assert_eq!(
                m.location(false, "example.com", "/old?x=1"),
                "http://example.com/new?x=1"
            );
            // A path built from the request's keeps it already: Sōzu answers.
            let config = EntrypointConfig {
                rewrite_path: Some("/v2$PATH[1]".to_string()),
                ..config
            };
            assert_eq!(config.middleware_redirect_status(), None);
        }
    }

    #[test]
    fn the_request_gives_what_the_route_does_not() {
        let m = middleware(&see_other(), prefix("/"), None);
        assert_eq!(
            m.location(false, "example.com:8080", "/see-other?x=1"),
            "http://example.com/see-other?x=1"
        );
        assert_eq!(m.location(true, "example.com", "/"), "https://example.com/");
    }

    #[test]
    fn the_route_gives_scheme_host_port_and_path() {
        let config = EntrypointConfig {
            redirect: Some(RedirectPolicy::TemporaryRedirect),
            redirect_scheme: Some(RedirectScheme::UseHttps),
            rewrite_host: Some("other.example.com".to_string()),
            rewrite_port: Some(8443),
            rewrite_path: Some("/elsewhere".to_string()),
            ..Default::default()
        };
        let m = middleware(&config, prefix("/"), None);
        assert_eq!(
            m.location(false, "example.com", "/temporary"),
            "https://other.example.com:8443/elsewhere"
        );
    }

    #[test]
    fn a_redirect_path_of_its_own_keeps_the_query() {
        let config = EntrypointConfig {
            rewrite_path: Some("/price$5".to_string()),
            ..see_other()
        };
        let m = middleware(&config, prefix("/"), None);
        assert_eq!(
            m.location(false, "example.com", "/old?token=abc"),
            "http://example.com/price$5?token=abc"
        );
    }

    #[test]
    fn a_default_port_is_left_out() {
        let config = EntrypointConfig {
            redirect_scheme: Some(RedirectScheme::UseHttps),
            rewrite_port: Some(443),
            ..see_other()
        };
        let m = middleware(&config, prefix("/"), None);
        assert_eq!(
            m.location(false, "example.com", "/"),
            "https://example.com/"
        );
    }

    #[test]
    fn a_template_makes_the_location() {
        let config = EntrypointConfig {
            redirect_template: Some(
                "%REDIRECT_LOCATION?from=%STATUS_CODE&id=%REQUEST_ID".to_string(),
            ),
            ..see_other()
        };
        let m = middleware(&config, prefix("/"), None);
        let response = m.respond("http://example.com/a", "GET example.com/a", "01ID");
        assert_eq!(
            response.headers()[header::LOCATION],
            "http://example.com/a?from=303&id=01ID"
        );
    }

    #[test]
    fn a_response_template_makes_the_response() {
        let config = EntrypointConfig {
            redirect_template: Some(
                "HTTP/1.1 301 Moved\r\nLocation: %REDIRECT_LOCATION\r\nContent-Length: 4\r\n\r\nmoved"
                    .to_string(),
            ),
            ..see_other()
        };
        let m = middleware(&config, prefix("/"), None);
        let response = m.respond("http://example.com/a", "GET example.com/a", "01ID");
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "http://example.com/a");
        assert!(response.headers().get(header::CONTENT_LENGTH).is_none());
    }

    #[test]
    fn the_https_port_is_left_out_of_an_http_redirect() {
        let config = EntrypointConfig {
            https_redirect_port: Some(443),
            ..see_other()
        };
        let m = middleware(&config, prefix("/"), None);
        assert_eq!(m.location(false, "example.com", "/"), "http://example.com/");
    }

    #[test]
    fn the_https_listener_port_is_the_fallback() {
        let config = EntrypointConfig {
            redirect_scheme: Some(RedirectScheme::UseHttps),
            https_redirect_port: Some(8443),
            ..see_other()
        };
        let m = middleware(&config, prefix("/"), None);
        assert_eq!(
            m.location(false, "example.com", "/"),
            "https://example.com:8443/"
        );
    }

    #[test]
    fn a_redirect_host_takes_the_captures_of_the_route() {
        let config = EntrypointConfig {
            hostnames: vec!["*.example.com".to_string()],
            rewrite_host: Some("$HOST[1].example.org".to_string()),
            ..see_other()
        };
        let m = middleware(&config, prefix("/"), None);
        assert_eq!(
            m.location(false, "app.example.com:8080", "/"),
            "http://app.example.org/"
        );
    }

    #[test]
    fn a_prefix_replacement_keeps_the_rest_of_the_path() {
        let config = EntrypointConfig {
            path: Some(PathConfig {
                rule_type: PathRuleType::Prefix,
                value: "/old".to_string(),
            }),
            rewrite: Some(UrlRewrite {
                path: Some(PathRewrite::ReplacePrefixMatch("/new".to_string())),
                hostname: None,
            }),
            ..see_other()
        };
        let (rule, rewrite) = crate::proxy::sozu::path_and_rewrite("c", &config);
        let m = RedirectMiddleware::new(&config, &rule, rewrite).expect("a redirect");
        assert_eq!(
            m.location(false, "example.com", "/old/page?x=1"),
            "http://example.com/new/page?x=1"
        );
        assert_eq!(
            m.location(false, "example.com", "/old"),
            "http://example.com/new"
        );
    }

    #[test]
    fn a_full_path_replacement_keeps_the_query() {
        let config = EntrypointConfig {
            path: Some(PathConfig {
                rule_type: PathRuleType::Prefix,
                value: "/old".to_string(),
            }),
            rewrite: Some(UrlRewrite {
                path: Some(PathRewrite::ReplaceFullPath("/new".to_string())),
                hostname: None,
            }),
            ..see_other()
        };
        let (rule, rewrite) = crate::proxy::sozu::path_and_rewrite("c", &config);
        let m = RedirectMiddleware::new(&config, &rule, rewrite).expect("a redirect");
        assert_eq!(
            m.location(false, "example.com", "/old/page?x=1"),
            "http://example.com/new?x=1"
        );
    }

    #[test]
    fn a_redirect_path_takes_the_captures_of_the_route() {
        let config = EntrypointConfig {
            rewrite_path: Some("/v2$PATH[1]".to_string()),
            ..see_other()
        };
        let m = middleware(&config, prefix("/api"), None);
        assert_eq!(
            m.location(false, "example.com", "/api/users"),
            "http://example.com/v2/users"
        );
    }

    #[tokio::test]
    async fn the_redirect_is_answered() {
        let m = middleware(&see_other(), prefix("/"), None);
        let mut ctx = RequestCtx {
            host: "example.com".to_string(),
            client_addr: None,
            is_tls: false,
            method: axum::http::Method::POST,
            path: "/see-other".to_string(),
            client_encoding: None,
            pending_response_headers: Vec::new(),
            in_flight_guards: Vec::new(),
        };
        let mut req = Request::builder()
            .uri("/see-other")
            .body(Body::empty())
            .unwrap();
        match m.on_request(&mut ctx, &mut req).await {
            Flow::ShortCircuit(response) => {
                assert_eq!(response.status(), StatusCode::SEE_OTHER);
                assert_eq!(
                    response.headers()[header::LOCATION],
                    "http://example.com/see-other"
                );
            }
            Flow::Continue => panic!("the redirect should be answered"),
        }
    }
}
