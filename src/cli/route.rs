//! `sozune route <url>`: which route serves a request, and why the others do
//! not. Asked of the running instance through `POST /routes/resolve`, so the
//! answer is the live routing state, not a re-reading of the config.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::IpAddr;

use clap::Args;

use super::local_api_url;
use crate::proxy::resolve::{Outcome, Resolution, StepVerdict, Verdict};

#[derive(Args, Debug)]
pub struct RouteArgs {
    /// Absolute URL of the request, e.g. https://app.example.com/api/users
    pub url: String,

    /// Request method.
    #[arg(short = 'X', long, default_value = "GET")]
    pub method: String,

    /// Request header, as `Name: value`. Repeatable.
    #[arg(short = 'H', long = "header", value_name = "NAME: VALUE")]
    pub headers: Vec<String>,

    /// Address the client connects from. Rules on the client address (IP
    /// allow-list, client-IP matching) are not evaluated without it.
    #[arg(long, value_name = "IP")]
    pub client_ip: Option<IpAddr>,

    /// API user [env: SOZUNE_API_USER]. The password is read from
    /// SOZUNE_API_PASSWORD, or given as `user:password`.
    #[arg(short, long)]
    pub user: Option<String>,

    /// API base URL, when it is not reachable at `api.listen_address` from
    /// the config (e.g. http://10.0.0.5:3035).
    #[arg(long, value_name = "URL")]
    pub api: Option<String>,

    /// Print the API's JSON answer instead of the tree.
    #[arg(long)]
    pub json: bool,
}

/// Exit codes, the same with or without `--json`: 0 when a route serves the
/// request (proxied, redirected, ACME challenge), 1 when it is not served (no
/// route matches, or sozune answers it with an error), 2 when the question
/// could not be answered (API unreachable, credentials refused, invalid
/// request).
pub async fn run(args: RouteArgs, config_path: &str) -> i32 {
    match ask(&args, config_path).await {
        Ok((resolution, body)) => {
            if args.json {
                println!("{body}");
            } else {
                print!("{}", render(&args.method, &args.url, &resolution));
            }
            exit_code(&resolution)
        }
        Err(message) => {
            eprintln!("sozune route: {message}");
            2
        }
    }
}

/// The resolution, and the API's answer pretty-printed for `--json`.
async fn ask(args: &RouteArgs, config_path: &str) -> Result<(Resolution, String), String> {
    let api = api_url(args, config_path).await?;
    let (user, password) = credentials(args)?;
    let headers = parse_headers(&args.headers)?;

    let body = serde_json::json!({
        "url": args.url,
        "method": args.method,
        "headers": headers,
        "client_ip": args.client_ip,
    });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("cannot build the HTTP client: {e}"))?;
    let response = client
        .post(format!("{api}/routes/resolve"))
        .basic_auth(&user, Some(&password))
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| format!("cannot reach the API at {api} ({e}); is sozune running?"))?;

    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| format!("cannot read the API's answer: {e}"))?;
    match status.as_u16() {
        200 => {}
        401 => {
            return Err(format!(
                "the API refused the credentials of `{user}` (check --user and SOZUNE_API_PASSWORD)"
            ));
        }
        404 => {
            return Err(format!(
                "{api} does not know /routes/resolve; is it a sozune older than this command?"
            ));
        }
        _ => {
            let message = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
                .unwrap_or(text);
            return Err(format!("the API answered {status}: {message}"));
        }
    }

    let resolution: Resolution =
        serde_json::from_str(&text).map_err(|e| format!("cannot read the API's answer: {e}"))?;
    let pretty = serde_json::from_str::<serde_json::Value>(&text)
        .and_then(|v| serde_json::to_string_pretty(&v))
        .unwrap_or(text);
    Ok((resolution, pretty))
}

/// `--api`, or the API address from the config, which must have it enabled.
async fn api_url(args: &RouteArgs, config_path: &str) -> Result<String, String> {
    if let Some(api) = &args.api {
        return Ok(api.trim_end_matches('/').to_string());
    }
    // Only a missing file falls back to defaults, as for `serve`: a file that
    // exists but cannot be read would point the command at the wrong API.
    let mut config = match tokio::fs::read_to_string(config_path).await {
        Ok(content) => crate::config_load::parse_yaml(std::path::Path::new(config_path), &content)
            .map_err(|e| format!("cannot read `{config_path}`: {e}"))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => crate::config::AppConfig::default(),
        Err(e) => return Err(format!("cannot read `{config_path}`: {e}")),
    };
    config.apply_env_overrides();
    if !config.api.enabled {
        return Err(
            "the API is disabled in the config; `sozune route` asks the running instance \
             through it: enable `api`, or pass --api"
                .to_string(),
        );
    }
    local_api_url(&config.api.listen_address).ok_or_else(|| {
        format!(
            "cannot read the API address `{}`; pass --api",
            config.api.listen_address
        )
    })
}

/// `--user` (or SOZUNE_API_USER), with the password after a `:` or in
/// SOZUNE_API_PASSWORD.
fn credentials(args: &RouteArgs) -> Result<(String, String), String> {
    let user = args
        .user
        .clone()
        .or_else(|| std::env::var("SOZUNE_API_USER").ok())
        .filter(|u| !u.is_empty())
        .ok_or("the API needs a user: pass --user or set SOZUNE_API_USER")?;
    if let Some((name, password)) = user.split_once(':') {
        return Ok((name.to_string(), password.to_string()));
    }
    let password = std::env::var("SOZUNE_API_PASSWORD")
        .map_err(|_| format!("no password for `{user}`: set SOZUNE_API_PASSWORD"))?;
    Ok((user, password))
}

fn parse_headers(raw: &[String]) -> Result<BTreeMap<String, String>, String> {
    raw.iter()
        .map(|header| {
            header
                .split_once(':')
                .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
                .filter(|(name, _)| !name.is_empty())
                .ok_or_else(|| format!("header `{header}` is not `Name: value`"))
        })
        .collect()
}

fn exit_code(resolution: &Resolution) -> i32 {
    match resolution.outcome {
        Outcome::Proxied | Outcome::Redirected | Outcome::AcmeChallenge => 0,
        Outcome::Rejected | Outcome::NoRoute => 1,
    }
}

fn render(method: &str, url: &str, resolution: &Resolution) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{} {url}", method.to_ascii_uppercase());
    let _ = writeln!(out);

    let glyph = match resolution.outcome {
        Outcome::Proxied | Outcome::Redirected | Outcome::AcmeChallenge => "✓",
        Outcome::Rejected | Outcome::NoRoute => "✗",
    };
    let _ = writeln!(out, "{glyph} {}", resolution.summary);
    if let Some(status) = resolution.status {
        let _ = writeln!(out, "  sozune answers {status}");
    }
    if let Some(route) = &resolution.route {
        let source = route.source.as_deref().unwrap_or("unknown source");
        let _ = writeln!(
            out,
            "  route {} ({source}, priority {})",
            route.id, route.priority
        );
    }

    section(&mut out, "candidates", &resolution.candidates, |c| {
        let verdict = match c.verdict {
            Verdict::Shadowed => "shadowed",
            Verdict::Rejected => "rejected",
            Verdict::Refused => "refused",
        };
        (
            "✗",
            format!("{} · priority {} · {verdict}", c.name, c.priority),
            Some(c.reason.clone()),
        )
    });
    section(&mut out, "pipeline", &resolution.pipeline, |s| {
        let glyph = match s.verdict {
            StepVerdict::Pass => "✓",
            StepVerdict::Blocked => "✗",
            StepVerdict::Applies => "•",
            StepVerdict::NotEvaluated => "?",
        };
        (glyph, s.name.clone(), s.detail.clone())
    });
    section(&mut out, "backends", &resolution.backends, |b| {
        let glyph = if b.healthy { "✓" } else { "✗" };
        (glyph, b.address.clone(), b.reason.clone())
    });
    out
}

/// A titled tree, in the shape `sozune doctor` prints. Empty sections are
/// left out.
fn section<T>(
    out: &mut String,
    title: &str,
    items: &[T],
    line: impl Fn(&T) -> (&'static str, String, Option<String>),
) {
    if items.is_empty() {
        return;
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "{title}");
    let last = items.len() - 1;
    for (i, item) in items.iter().enumerate() {
        let (branch, cont) = if i == last {
            ("└─", "  ")
        } else {
            ("├─", "│ ")
        };
        let (glyph, text, detail) = line(item);
        let _ = writeln!(out, "{branch} {glyph} {text}");
        if let Some(detail) = detail {
            let _ = writeln!(out, "{cont}    {detail}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolution(json: serde_json::Value) -> Resolution {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn a_proxied_request_renders_its_route_candidates_and_backends() {
        let resolution = resolution(serde_json::json!({
            "outcome": "proxied",
            "status": null,
            "summary": "proxied by route `api`",
            "route": { "id": "http_api", "name": "api", "source": "docker", "priority": 10 },
            "candidates": [{
                "id": "http_web", "name": "web", "priority": 0,
                "verdict": "shadowed", "reason": "matches too, but `api` has a higher priority (10 > 0)"
            }],
            "pipeline": [
                { "name": "ip-allow-list", "verdict": "pass", "detail": null },
                { "name": "rate-limit", "verdict": "applies", "detail": "depends on the client's recent requests" }
            ],
            "backends": [
                { "address": "10.0.0.4:8080", "healthy": true, "reason": null },
                { "address": "10.0.0.5:8080", "healthy": false, "reason": "connection refused" }
            ]
        }));

        let out = render("get", "http://app.example.com/api/users", &resolution);

        assert!(out.starts_with("GET http://app.example.com/api/users\n"));
        assert!(out.contains("✓ proxied by route `api`"));
        assert!(out.contains("route http_api (docker, priority 10)"));
        assert!(out.contains("└─ ✗ web · priority 0 · shadowed"));
        assert!(out.contains("├─ ✓ ip-allow-list"));
        assert!(out.contains("└─ • rate-limit"));
        assert!(out.contains("└─ ✗ 10.0.0.5:8080\n      connection refused"));
        assert_eq!(exit_code(&resolution), 0);
    }

    #[test]
    fn no_route_shows_the_status_and_exits_1() {
        let resolution = resolution(serde_json::json!({
            "outcome": "no_route",
            "status": 404,
            "summary": "no route for host `exmple.com`; did you mean `example.com`?",
            "route": null,
            "candidates": [],
            "pipeline": [],
            "backends": []
        }));

        let out = render("GET", "http://exmple.com/", &resolution);

        assert!(out.contains("✗ no route for host `exmple.com`; did you mean `example.com`?"));
        assert!(out.contains("sozune answers 404"));
        assert!(!out.contains("candidates"));
        assert_eq!(exit_code(&resolution), 1);
    }

    #[test]
    fn headers_must_be_name_colon_value() {
        let parsed = parse_headers(&["X-Tenant: acme".to_string()]).unwrap();
        assert_eq!(parsed.get("X-Tenant").map(String::as_str), Some("acme"));

        assert!(parse_headers(&["X-Tenant".to_string()]).is_err());
        assert!(parse_headers(&[": acme".to_string()]).is_err());
    }

    #[test]
    fn a_password_can_follow_the_user() {
        let args = RouteArgs {
            url: "http://example.com/".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            client_ip: None,
            user: Some("alice:secret".to_string()),
            api: None,
            json: false,
        };
        assert_eq!(
            credentials(&args).unwrap(),
            ("alice".to_string(), "secret".to_string())
        );
    }

    #[test]
    fn the_api_is_reached_on_loopback_when_bound_everywhere() {
        assert_eq!(
            local_api_url("0.0.0.0:3035").as_deref(),
            Some("http://127.0.0.1:3035")
        );
        assert_eq!(
            local_api_url("[::]:3035").as_deref(),
            Some("http://[::1]:3035")
        );
        assert_eq!(
            local_api_url("10.0.0.5:3035").as_deref(),
            Some("http://10.0.0.5:3035")
        );
    }
}
