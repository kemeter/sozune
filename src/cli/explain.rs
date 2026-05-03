use clap::Args;

use crate::labels::diagnostic::DiagnosticCode;

#[derive(Args, Debug)]
pub struct ExplainArgs {
    /// Diagnostic code to explain (e.g. E002, W009, I001).
    pub code: String,
}

pub fn run(args: ExplainArgs) -> i32 {
    let code = args.code.trim().to_uppercase();
    match lookup(&code) {
        Some(entry) => {
            print!("{}", render(entry));
            0
        }
        None => {
            eprintln!(
                "Unknown diagnostic code: {code}\nKnown codes: {}",
                all_codes().join(", ")
            );
            2
        }
    }
}

struct Entry {
    code: &'static str,
    title: &'static str,
    severity: &'static str,
    cause: &'static str,
    effect: &'static str,
    fix: &'static str,
    example: Option<&'static str>,
}

fn render(e: &Entry) -> String {
    let mut out = String::new();
    out.push_str(&format!("{} — {}\n", e.code, e.title));
    out.push_str(&format!("severity: {}\n\n", e.severity));
    out.push_str("Cause\n");
    out.push_str(&format!("  {}\n\n", e.cause));
    out.push_str("Effect\n");
    out.push_str(&format!("  {}\n\n", e.effect));
    out.push_str("Fix\n");
    out.push_str(&format!("  {}\n", e.fix));
    if let Some(ex) = e.example {
        out.push_str("\nExample\n");
        for line in ex.lines() {
            out.push_str(&format!("  {line}\n"));
        }
    }
    out
}

fn lookup(code: &str) -> Option<&'static Entry> {
    ENTRIES.iter().find(|e| e.code == code)
}

fn all_codes() -> Vec<&'static str> {
    ENTRIES.iter().map(|e| e.code).collect()
}

const ENTRIES: &[Entry] = &[
    Entry {
        code: "E001",
        title: "Routing disabled for this candidate",
        severity: "error",
        cause: "The label `sozune.enable` is missing or set to a falsey value, and the provider does not enable routing by default.",
        effect: "The candidate is silently skipped. No frontend or backend is registered.",
        fix: "Set `sozune.enable=true` on the container/service, or enable the provider's `enabled_default` setting.",
        example: Some("docker run -l sozune.enable=true -l sozune.http.web.host=example.com nginx"),
    },
    Entry {
        code: "E002",
        title: "Missing host label",
        severity: "error",
        cause: "An HTTP entrypoint was declared but no `sozune.http.<name>.host` label was provided.",
        effect: "The entrypoint is dropped. Sōzu cannot match requests without a hostname.",
        fix: "Add a host label for the entrypoint. The hostname must be a valid DNS name.",
        example: Some("sozune.http.web.host=api.example.com"),
    },
    Entry {
        code: "E003",
        title: "Container inspection failed",
        severity: "error",
        cause: "The provider could not query the container/service runtime to read its labels or networking info (Docker socket unreachable, Kubernetes API timeout, etc.).",
        effect: "The candidate is skipped. Routing for this workload is not updated.",
        fix: "Verify the provider's connectivity. For Docker: `docker ps` should work; check socket permissions. For Kubernetes: check kubeconfig and cluster reachability.",
        example: None,
    },
    Entry {
        code: "E004",
        title: "No services exposed",
        severity: "error",
        cause: "The candidate has no exposed port that sozune can route to (no `EXPOSE`, no port mapping, no service port).",
        effect: "Skipped. Sōzu has nowhere to forward traffic.",
        fix: "Expose at least one port on the container, or set `sozune.http.<name>.port` explicitly.",
        example: Some("sozune.http.web.port=8080"),
    },
    Entry {
        code: "E005",
        title: "Missing TCP entrypoint name",
        severity: "error",
        cause: "A `sozune.tcp.<name>.*` label was set but `<name>` is empty or invalid.",
        effect: "The TCP entrypoint is dropped.",
        fix: "Use a non-empty alphanumeric name for the entrypoint segment.",
        example: Some("sozune.tcp.db.port=5432  # \"db\" is the entrypoint name"),
    },
    Entry {
        code: "W001",
        title: "Invalid port value",
        severity: "warning",
        cause: "The port label contains a value that is not a positive integer between 0 and 65535.",
        effect: "The invalid port is ignored. sozune falls back to the candidate's default exposed port if any.",
        fix: "Set the port to an integer in [0, 65535].",
        example: Some("sozune.http.web.port=8080"),
    },
    Entry {
        code: "W002",
        title: "Invalid priority value",
        severity: "warning",
        cause: "The priority label is not a valid integer.",
        effect: "Falls back to the default priority (0). Route ordering may differ from intent.",
        fix: "Use an integer. Higher values are matched first.",
        example: Some("sozune.http.web.priority=10"),
    },
    Entry {
        code: "W003",
        title: "Invalid backend timeout",
        severity: "warning",
        cause: "The `backend_timeout` value is not a positive integer (milliseconds).",
        effect: "Default timeout applies.",
        fix: "Express the timeout in milliseconds as a positive integer.",
        example: Some("sozune.http.web.backend_timeout=30000  # 30s"),
    },
    Entry {
        code: "W004",
        title: "Invalid rate limit configuration",
        severity: "warning",
        cause: "Rate-limit fields (`average`, `burst`) are missing, malformed, or inconsistent.",
        effect: "Rate limiting is not enabled for this entrypoint.",
        fix: "Set both `ratelimit.average` (req/s) and `ratelimit.burst` (allowed peak) to positive integers.",
        example: Some("sozune.http.api.ratelimit.average=100\nsozune.http.api.ratelimit.burst=200"),
    },
    Entry {
        code: "W005",
        title: "Invalid redirect policy",
        severity: "warning",
        cause: "The redirect policy value is not one of the accepted options.",
        effect: "The redirect rule is dropped.",
        fix: "Use one of: `forward`, `permanent`, `unauthorized`.",
        example: Some("sozune.http.web.redirect.policy=permanent"),
    },
    Entry {
        code: "W006",
        title: "Invalid redirect scheme",
        severity: "warning",
        cause: "The redirect scheme value is not one of the accepted options.",
        effect: "The redirect rule is dropped.",
        fix: "Use one of: `use_same`, `use_http`, `use_https`.",
        example: Some("sozune.http.web.redirect.scheme=use_https"),
    },
    Entry {
        code: "W007",
        title: "Malformed basic auth entry",
        severity: "warning",
        cause: "A basic-auth user entry does not match the `username:password_hash` format.",
        effect: "The malformed entry is skipped. Other valid users still apply.",
        fix: "Provide credentials as `user:bcrypt_hash`. Generate hashes with `htpasswd -nbB user pass`.",
        example: Some("sozune.http.web.auth.basic=admin:$2y$05$...hash..."),
    },
    Entry {
        code: "W008",
        title: "Blocked header injection",
        severity: "warning",
        cause: "A header in `headers.*` is on the protected list (Host, Connection, Content-Length, etc.) and cannot be safely overridden.",
        effect: "The header is not injected.",
        fix: "Remove the protected header from your config. If you need to set it, use a dedicated label (e.g. host rewriting).",
        example: None,
    },
    Entry {
        code: "W009",
        title: "Network not found on container",
        severity: "warning",
        cause: "The configured `network` label references a Docker network the container is not attached to.",
        effect: "Falls back to another available network.",
        fix: "Attach the container to the network, or remove the `network` label to let sozune pick one.",
        example: Some("docker network connect mynet mycontainer"),
    },
    Entry {
        code: "W010",
        title: "No reachable IP, fell back to localhost",
        severity: "warning",
        cause: "sozune could not determine a routable IP for the candidate from any provider network.",
        effect: "Routes resolve to 127.0.0.1, which is almost certainly wrong for a remote container.",
        fix: "Ensure the container has a network with an IP address visible from sozune (host network, shared bridge, or pod network).",
        example: None,
    },
    Entry {
        code: "W011",
        title: "Empty basic auth list",
        severity: "warning",
        cause: "`auth.basic` was set but contained no usable entries after parsing.",
        effect: "Authentication is not applied. The endpoint is open.",
        fix: "Provide at least one valid `user:hash` entry, or remove the `auth.basic` label entirely.",
        example: None,
    },
    Entry {
        code: "W012",
        title: "Invalid protocol",
        severity: "warning",
        cause: "The protocol segment of a label is not one of the accepted values.",
        effect: "The entrypoint is dropped.",
        fix: "Use `http`, `tcp`, or `udp` as the protocol segment.",
        example: Some("sozune.http.web.host=...  # protocol is `http`"),
    },
    Entry {
        code: "W013",
        title: "Unknown label",
        severity: "warning",
        cause: "A label starting with `sozune.` does not match any known field.",
        effect: "The label is ignored. May indicate a typo.",
        fix: "Check the label spelling. See https://sozune.dev/docs/labels for the supported set. The diagnostic message often suggests a likely correction.",
        example: None,
    },
    Entry {
        code: "W014",
        title: "Invalid HTTP method",
        severity: "warning",
        cause: "A method listed in `methods=...` is not a recognized HTTP verb.",
        effect: "The invalid verb is dropped. Other valid methods in the same label still apply.",
        fix: "Use one of: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, CONNECT, TRACE. Methods are case-insensitive (uppercased internally).",
        example: Some("sozune.http.api.methods=GET,POST,PATCH"),
    },
    Entry {
        code: "W015",
        title: "ACME enabled but no TLS entrypoint",
        severity: "warning",
        cause: "`acme.enabled=true` in the configuration, but no HTTP entrypoint declares `tls=true`. ACME has nothing to provision.",
        effect: "The ACME manager runs but never requests a certificate.",
        fix: "Either disable ACME (`acme.enabled=false`) or set `sozune.http.<svc>.tls=true` on at least one entrypoint.",
        example: Some("sozune.http.web.tls=true"),
    },
    Entry {
        code: "W016",
        title: "https_redirect without tls",
        severity: "warning",
        cause: "`httpsRedirect=true` was set on an entrypoint that has `tls=false`. The redirect target (HTTPS) is not configured for this hostname.",
        effect: "Clients are redirected to a port that has no TLS listener for this hostname; they get a connection error.",
        fix: "Set `tls=true` on the same entrypoint (and configure ACME or a static cert), or remove `httpsRedirect`.",
        example: Some("sozune.http.web.tls=true\nsozune.http.web.httpsRedirect=true"),
    },
    Entry {
        code: "W017",
        title: "rate_limit.burst lower than rate_limit.average",
        severity: "warning",
        cause: "Token bucket configured with `burst < average`. The burst capacity (max tokens) cannot exceed the refill rate (average), making the burst window meaningless.",
        effect: "Effective rate limit is `burst`, not `average`. Bursts of traffic are rejected sooner than expected.",
        fix: "Set `burst >= average`. A common pattern is `burst = 2 * average` to absorb short spikes.",
        example: Some("sozune.http.api.ratelimit.average=100\nsozune.http.api.ratelimit.burst=200"),
    },
    Entry {
        code: "W018",
        title: "Route collision (same host + path)",
        severity: "warning",
        cause: "Two or more candidates declare an entrypoint matching the same `(host, path)` pair.",
        effect: "Only the highest-priority candidate is reachable; the others are shadowed and silently unreachable.",
        fix: "Use distinct hostnames or paths. If the overlap is intentional, set `sozune.http.<svc>.priority=N` to make precedence explicit (higher wins).",
        example: Some("sozune.http.api.priority=10"),
    },
    Entry {
        code: "I001",
        title: "Path defaulted",
        severity: "info",
        cause: "No `sozune.http.<name>.path` label was provided.",
        effect: "The entrypoint matches `/` (everything under the host). This is usually intended.",
        fix: "If you need narrower matching, set `sozune.http.<name>.path` (prefix, exact, or regex).",
        example: Some("sozune.http.api.path=/v1"),
    },
    Entry {
        code: "I002",
        title: "Port defaulted",
        severity: "info",
        cause: "No explicit port label was set; sozune used the candidate's first exposed port.",
        effect: "Routing works as long as the right port is exposed first. Brittle if the container exposes several ports.",
        fix: "Set `sozune.http.<name>.port` explicitly to lock the choice.",
        example: Some("sozune.http.web.port=8080"),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_diagnostic_code_has_an_entry() {
        let codes = [
            DiagnosticCode::E001Disabled,
            DiagnosticCode::E002MissingHost,
            DiagnosticCode::E003InspectFailed,
            DiagnosticCode::E004NoServices,
            DiagnosticCode::E005MissingTcpEntrypoint,
            DiagnosticCode::W001InvalidPort,
            DiagnosticCode::W002InvalidPriority,
            DiagnosticCode::W003InvalidTimeout,
            DiagnosticCode::W004InvalidRateLimit,
            DiagnosticCode::W005InvalidRedirectPolicy,
            DiagnosticCode::W006InvalidRedirectScheme,
            DiagnosticCode::W007MalformedBasicAuthEntry,
            DiagnosticCode::W008BlockedHeader,
            DiagnosticCode::W009NetworkNotFound,
            DiagnosticCode::W010NoIpFellBackToLocalhost,
            DiagnosticCode::W011EmptyBasicAuth,
            DiagnosticCode::W012InvalidProtocol,
            DiagnosticCode::W013UnknownLabel,
            DiagnosticCode::W014InvalidMethod,
            DiagnosticCode::W015AcmeWithoutTls,
            DiagnosticCode::W016HttpsRedirectWithoutTls,
            DiagnosticCode::W017RateLimitBurstBelowAverage,
            DiagnosticCode::W018RouteCollision,
            DiagnosticCode::I001PathDefaulted,
            DiagnosticCode::I002PortDefaulted,
        ];
        for c in codes {
            assert!(
                lookup(c.as_str()).is_some(),
                "missing explain entry for {}",
                c.as_str()
            );
        }
    }

    #[test]
    fn lookup_is_case_insensitive_via_run() {
        assert!(lookup("E001").is_some());
        assert!(lookup("w013").is_none(), "lookup itself is case-sensitive");
    }

    #[test]
    fn render_includes_sections() {
        let entry = lookup("E002").unwrap();
        let out = render(entry);
        assert!(out.contains("E002"));
        assert!(out.contains("Cause"));
        assert!(out.contains("Effect"));
        assert!(out.contains("Fix"));
        assert!(out.contains("Example"));
    }

    #[test]
    fn unknown_code_returns_nonzero() {
        let rc = run(ExplainArgs {
            code: "X999".into(),
        });
        assert_eq!(rc, 2);
    }

    #[test]
    fn known_code_returns_zero() {
        let rc = run(ExplainArgs {
            code: "e002".into(),
        });
        assert_eq!(rc, 0);
    }
}
