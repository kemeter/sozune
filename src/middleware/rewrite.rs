//! Rewrites of the path the backend receives, and redirects by regex: the
//! `replacePath`, `replacePathRegex` and `redirectRegex` of a route, as
//! Traefik's middlewares of these names behave.

use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, Response, StatusCode, Uri, header, uri};
use regex::Regex;
use tracing::warn;

use super::chain::{Flow, Middleware, RequestCtx};
use super::diag;
use crate::model::{RedirectRegex, RegexReplacement, valid_replace_path};

/// The header carrying the path the request had before a rewrite.
const REPLACED_PATH: &str = "x-replaced-path";

/// What a path cannot hold as is: a replacement writing one of these gets it
/// percent-encoded, as Go does for Traefik. `%` stays, for the encodings the
/// path or the replacement already carry.
const NOT_IN_PATH: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

/// Replaces the path of the request before it reaches the backend: with a
/// fixed path, then where a regex matches it. The query is kept.
pub struct ReplacePathMiddleware {
    path: Option<String>,
    regex: Option<(Regex, String)>,
}

impl ReplacePathMiddleware {
    /// The rewrites of a route, `None` when it has none that can apply. An
    /// invalid one, which a provider without label diagnostics may hand
    /// over, is logged and left out.
    pub fn new(path: Option<&str>, regex: Option<&RegexReplacement>, host: &str) -> Option<Self> {
        let path = path.and_then(|p| {
            if valid_replace_path(p) {
                Some(p.to_string())
            } else {
                warn!("replace_path `{p}` on {host} is not a path, ignoring");
                None
            }
        });
        let regex = regex.and_then(|r| match Regex::new(&r.regex) {
            Ok(_) if r.replacement.is_empty() => {
                warn!("replace_path_regex on {host} has an empty replacement, ignoring");
                None
            }
            Ok(regex) => Some((regex, r.replacement.clone())),
            Err(e) => {
                warn!("replace_path_regex on {host} does not compile, ignoring: {e}");
                None
            }
        });
        (path.is_some() || regex.is_some()).then_some(Self { path, regex })
    }

    /// The path the backend receives instead of `current`, `None` when it
    /// keeps it.
    fn rewrite(&self, current: &str) -> Option<String> {
        let mut new = self.path.clone();
        if let Some((regex, replacement)) = &self.regex {
            let base = new.as_deref().unwrap_or(current);
            if regex.is_match(base) {
                new = Some(regex.replace_all(base, replacement.as_str()).into_owned());
            }
        }
        new.map(|p| {
            let p = percent_encoding::utf8_percent_encode(&p, NOT_IN_PATH).to_string();
            if p.starts_with('/') {
                p
            } else {
                format!("/{p}")
            }
        })
    }
}

#[async_trait::async_trait]
impl Middleware for ReplacePathMiddleware {
    fn name(&self) -> &'static str {
        "replace-path"
    }

    async fn on_request(&self, _ctx: &mut RequestCtx, req: &mut Request<Body>) -> Flow {
        let current = req.uri().path().to_string();
        let Some(path) = self.rewrite(&current) else {
            return Flow::Continue;
        };
        let path_and_query = match req.uri().query() {
            Some(query) => format!("{path}?{query}"),
            None => path,
        };
        let mut parts = req.uri().clone().into_parts();
        parts.path_and_query = match path_and_query.parse::<uri::PathAndQuery>() {
            Ok(pq) => Some(pq),
            Err(_) => {
                return Flow::ShortCircuit(diag::internal_error("replace-path-invalid-result"));
            }
        };
        let Ok(new_uri) = Uri::from_parts(parts) else {
            return Flow::ShortCircuit(diag::internal_error("replace-path-invalid-result"));
        };
        if let Ok(value) = HeaderValue::from_str(&current) {
            req.headers_mut().insert(REPLACED_PATH, value);
        }
        *req.uri_mut() = new_uri;
        Flow::Continue
    }
}

/// Redirects the requests whose URL, `scheme://host/path?query`, matches a
/// regex, to that URL with the matches replaced. A request it does not
/// match, or that it would send to its own URL, goes on.
pub struct RedirectRegexMiddleware {
    regex: Regex,
    replacement: String,
    permanent: bool,
}

impl RedirectRegexMiddleware {
    /// The redirect of a route, `None` (logged) when its regex does not
    /// compile.
    pub fn new(config: &RedirectRegex, host: &str) -> Option<Self> {
        match Regex::new(&config.regex) {
            Ok(regex) => Some(Self {
                regex,
                replacement: config.replacement.clone(),
                permanent: config.permanent,
            }),
            Err(e) => {
                warn!("redirect_regex on {host} does not compile, ignoring: {e}");
                None
            }
        }
    }

    /// `301` / `302` for a `GET`, `308` / `307` otherwise: those keep the
    /// method and body.
    fn status(&self, method: &Method) -> StatusCode {
        match (self.permanent, method == Method::GET) {
            (true, true) => StatusCode::MOVED_PERMANENTLY,
            (true, false) => StatusCode::PERMANENT_REDIRECT,
            (false, true) => StatusCode::FOUND,
            (false, false) => StatusCode::TEMPORARY_REDIRECT,
        }
    }
}

#[async_trait::async_trait]
impl Middleware for RedirectRegexMiddleware {
    fn name(&self) -> &'static str {
        "redirect-regex"
    }

    async fn on_request(&self, ctx: &mut RequestCtx, req: &mut Request<Body>) -> Flow {
        // The listener's scheme, as its frontend names it.
        let is_tls = req
            .headers()
            .get(super::SCHEME_HEADER)
            .map_or(ctx.is_tls, |scheme| scheme == "https");
        let scheme = if is_tls { "https" } else { "http" };
        let path_and_query = req.uri().path_and_query().map_or("/", |pq| pq.as_str());
        let url = format!("{scheme}://{}{path_and_query}", ctx.host);
        if !self.regex.is_match(&url) {
            return Flow::Continue;
        }
        let location = self.regex.replace_all(&url, self.replacement.as_str());
        if location == url {
            return Flow::Continue;
        }
        let Ok(location) = HeaderValue::from_str(&location) else {
            return Flow::ShortCircuit(diag::internal_error("redirect-regex-invalid-location"));
        };
        let status = self.status(req.method());
        let mut resp = Response::new(Body::from(
            status.canonical_reason().unwrap_or_default().to_string(),
        ));
        *resp.status_mut() = status;
        resp.headers_mut().insert(header::LOCATION, location);
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        Flow::ShortCircuit(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(host: &str, is_tls: bool) -> RequestCtx {
        RequestCtx {
            host: host.to_string(),
            client_addr: None,
            is_tls,
            method: Method::GET,
            path: "/".to_string(),
            client_encoding: None,
            pending_response_headers: Vec::new(),
            in_flight_guards: Vec::new(),
        }
    }

    fn request(method: Method, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    fn replace(path: Option<&str>, regex: Option<(&str, &str)>) -> ReplacePathMiddleware {
        let regex = regex.map(|(regex, replacement)| RegexReplacement {
            regex: regex.to_string(),
            replacement: replacement.to_string(),
        });
        ReplacePathMiddleware::new(path, regex.as_ref(), "example.com").unwrap()
    }

    async fn forwarded(mw: &ReplacePathMiddleware, uri: &str) -> Request<Body> {
        let mut req = request(Method::GET, uri);
        match mw
            .on_request(&mut ctx("example.com", false), &mut req)
            .await
        {
            Flow::Continue => req,
            Flow::ShortCircuit(resp) => panic!("answered {}", resp.status()),
        }
    }

    #[tokio::test]
    async fn replace_path_keeps_the_query_and_records_the_old_path() {
        let req = forwarded(&replace(Some("/foo"), None), "/bar/baz?x=1").await;
        assert_eq!(req.uri(), "/foo?x=1");
        assert_eq!(req.headers()[REPLACED_PATH], "/bar/baz");
    }

    #[tokio::test]
    async fn replace_path_regex_replaces_the_matches() {
        let mw = replace(None, Some(("^/foo/(.*)", "/bar/$1")));
        let req = forwarded(&mw, "/foo/baz?x=1").await;
        assert_eq!(req.uri(), "/bar/baz?x=1");
        assert_eq!(req.headers()[REPLACED_PATH], "/foo/baz");
    }

    #[tokio::test]
    async fn replace_path_regex_replaces_every_match_anywhere() {
        let mw = replace(None, Some(("v1", "v2")));
        assert_eq!(forwarded(&mw, "/api/v1/x/v1").await.uri(), "/api/v2/x/v2");
    }

    #[tokio::test]
    async fn a_path_the_regex_does_not_match_is_kept() {
        let mw = replace(None, Some(("^/foo/(.*)", "/bar/$1")));
        let req = forwarded(&mw, "/other?x=1").await;
        assert_eq!(req.uri(), "/other?x=1");
        assert!(!req.headers().contains_key(REPLACED_PATH));
    }

    #[tokio::test]
    async fn a_result_without_a_leading_slash_gets_one() {
        let mw = replace(None, Some(("^/foo/(.*)", "$1")));
        assert_eq!(forwarded(&mw, "/foo/bar").await.uri(), "/bar");
    }

    #[tokio::test]
    async fn characters_a_path_cannot_hold_are_encoded() {
        let mw = replace(None, Some(("^/foo", "/a b?c#d")));
        let req = forwarded(&mw, "/foo?x=1").await;
        assert_eq!(req.uri(), "/a%20b%3Fc%23d?x=1");
        assert_eq!(req.uri().query(), Some("x=1"));
    }

    #[tokio::test]
    async fn existing_encodings_are_kept() {
        let mw = replace(None, Some(("^/foo/(.*)", "/bar/$1")));
        assert_eq!(forwarded(&mw, "/foo/a%2Fb").await.uri(), "/bar/a%2Fb");
    }

    #[tokio::test]
    async fn the_regex_applies_to_the_replaced_path() {
        let mw = replace(Some("/fixed/one"), Some(("one", "two")));
        assert_eq!(forwarded(&mw, "/x").await.uri(), "/fixed/two");
    }

    #[test]
    fn invalid_rewrites_are_left_out() {
        let bad_regex = RegexReplacement {
            regex: "(".to_string(),
            replacement: "/x".to_string(),
        };
        let empty_replacement = RegexReplacement {
            regex: "x".to_string(),
            replacement: String::new(),
        };
        assert!(ReplacePathMiddleware::new(Some("nope"), None, "h").is_none());
        assert!(ReplacePathMiddleware::new(None, Some(&bad_regex), "h").is_none());
        assert!(ReplacePathMiddleware::new(None, Some(&empty_replacement), "h").is_none());
    }

    fn redirect(regex: &str, replacement: &str, permanent: bool) -> RedirectRegexMiddleware {
        RedirectRegexMiddleware::new(
            &RedirectRegex {
                regex: regex.to_string(),
                replacement: replacement.to_string(),
                permanent,
            },
            "example.com",
        )
        .unwrap()
    }

    async fn answer(
        mw: &RedirectRegexMiddleware,
        host: &str,
        tls: bool,
        method: Method,
        uri: &str,
    ) -> Option<Response<Body>> {
        let mut req = request(method, uri);
        match mw.on_request(&mut ctx(host, tls), &mut req).await {
            Flow::Continue => None,
            Flow::ShortCircuit(resp) => Some(resp),
        }
    }

    #[tokio::test]
    async fn redirect_regex_rewrites_the_whole_url() {
        let mw = redirect(
            r"^https?://old\.example\.com/(.*)",
            "https://www.example.com/$1",
            false,
        );
        let resp = answer(&mw, "old.example.com", false, Method::GET, "/a/b?x=1")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()[header::LOCATION],
            "https://www.example.com/a/b?x=1"
        );
    }

    #[tokio::test]
    async fn redirect_regex_sees_the_scheme_and_port() {
        let mw = redirect(r"^https://([^/]+):8443/(.*)", "https://$1/$2", true);
        let resp = answer(&mw, "example.com:8443", true, Method::GET, "/x")
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(resp.headers()[header::LOCATION], "https://example.com/x");
        assert!(
            answer(&mw, "example.com:8443", false, Method::GET, "/x")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn redirect_regex_keeps_the_method_for_other_than_get() {
        let temporary = redirect("^(.*)/old$", "$1/new", false);
        let permanent = redirect("^(.*)/old$", "$1/new", true);
        let status = |r: Option<Response<Body>>| r.unwrap().status();
        assert_eq!(
            status(answer(&temporary, "h", false, Method::POST, "/old").await),
            StatusCode::TEMPORARY_REDIRECT
        );
        assert_eq!(
            status(answer(&permanent, "h", false, Method::POST, "/old").await),
            StatusCode::PERMANENT_REDIRECT
        );
    }

    #[tokio::test]
    async fn a_request_the_regex_does_not_match_goes_on() {
        let mw = redirect(
            r"^http://old\.example\.com/(.*)",
            "http://new.example.com/$1",
            false,
        );
        assert!(
            answer(&mw, "other.example.com", false, Method::GET, "/")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_redirect_to_the_same_url_goes_on() {
        let mw = redirect("^(http://.*)$", "$1", true);
        assert!(
            answer(&mw, "example.com", false, Method::GET, "/x")
                .await
                .is_none()
        );
    }
}
