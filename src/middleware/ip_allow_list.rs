//! Per-route IP allow-list with secure `X-Forwarded-For` handling.
//!
//! The middleware short-circuits with `403 Forbidden` when the resolved client
//! IP is not in the allow-list. It runs **first** in the chain so a denied
//! client never reaches auth, rate-limit, or the backend.
//!
//! ## Client-IP resolution
//!
//! `X-Forwarded-For` is *attacker-controllable*. A naïve "leftmost XFF entry"
//! resolver — common in proxies, easy to get wrong — lets any client on the
//! internet spoof their address and bypass the allow-list:
//!
//! ```text
//! curl -H "X-Forwarded-For: 10.0.0.1" https://gateway/  # impersonates 10.0.0.1
//! ```
//!
//! To make `X-Forwarded-For` trustworthy we need to know which network hop
//! actually attached it. That information lives in
//! [`ProxyConfig::trusted_proxies`] (CIDRs of reverse-proxies that sit in
//! front of Sōzune):
//!
//! - **No trusted proxy configured** (the safe default): `X-Forwarded-For`
//!   is **ignored entirely** and the direct TCP peer is the client.
//! - **Trusted proxies configured**: parse `X-Forwarded-For` right-to-left,
//!   skipping every entry that matches a trusted-proxy CIDR. The first
//!   non-trusted entry is the client. If every entry is trusted (very long
//!   chain of internal hops), the leftmost stays as the client. If no entry
//!   parses, fall back to the TCP peer.
//!
//! The TCP peer itself is *also* checked against `trusted_proxies` — when an
//! untrusted peer sends `X-Forwarded-For`, the header is dropped (an untrusted
//! peer cannot speak about who is behind it).
//!
//! ## Fail-closed entries
//!
//! Allow-list entries that fail to parse are logged and dropped — a typo
//! can only ever *narrow* the allow-list, never *widen* it. If every entry
//! is invalid, the middleware isn't installed (the route stays open instead
//! of being silently black-holed); this is surfaced as a diagnostic.

use std::net::IpAddr;
use std::str::FromStr;

use axum::body::Body;
use axum::http::Request;
use ipnet::IpNet;
use tracing::{debug, warn};

use super::chain::{Flow, Middleware, RequestCtx};
use super::diag;

/// Parsed allow-list. Owns the compiled CIDR networks so each request match
/// is just a linear walk over already-parsed entries.
pub struct IpAllowList {
    allowed: Vec<IpNet>,
}

impl IpAllowList {
    pub fn new(entries: &[String]) -> Self {
        Self {
            allowed: parse_cidrs(entries, "ip_allow_list"),
        }
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        let ip = unmap_ipv4(ip);
        self.allowed.iter().any(|net| net.contains(&ip))
    }

    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

/// Compiled list of trusted reverse-proxy CIDRs. Empty means "trust nothing"
/// → `X-Forwarded-For` is always ignored.
#[derive(Clone, Default)]
pub struct TrustedProxies {
    nets: Vec<IpNet>,
}

impl TrustedProxies {
    pub fn new(entries: &[String]) -> Self {
        Self {
            nets: parse_cidrs(entries, "trusted_proxies"),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = unmap_ipv4(ip);
        self.nets.iter().any(|net| net.contains(&ip))
    }
}

/// Resolve the client IP from the request and the TCP peer.
///
/// Algorithm (see module docstring for the rationale):
///
/// 1. If `trusted_proxies` is empty → return the TCP peer (XFF ignored).
/// 2. If `trusted_proxies` is non-empty **and** the TCP peer is *not* trusted
///    → return the TCP peer (XFF dropped, the peer is the client itself).
/// 3. Otherwise, walk `X-Forwarded-For` **right to left**, skipping trusted
///    entries; the first non-trusted entry is the client.
/// 4. If every XFF entry is trusted or none parses → fall back to the TCP
///    peer.
pub fn resolve_client_ip(
    req: &Request<Body>,
    ctx: &RequestCtx,
    trusted: &TrustedProxies,
) -> Option<IpAddr> {
    let peer = ctx.client_addr.map(|a| a.ip());

    // Cases 1 and 2: XFF is not trustworthy → return the TCP peer.
    if trusted.is_empty() {
        return peer;
    }
    let Some(peer_ip) = peer else {
        return None;
    };
    if !trusted.contains(peer_ip) {
        return Some(peer_ip);
    }

    // Case 3: TCP peer is a trusted proxy. Walk XFF right to left, skipping
    // trusted hops. The first non-trusted entry is the real client.
    if let Some(value) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        for token in value.split(',').rev() {
            let token = token.trim();
            if let Ok(ip) = IpAddr::from_str(token) {
                if !trusted.contains(ip) {
                    return Some(ip);
                }
            }
        }
    }

    // Case 4: every XFF entry was trusted (long internal chain) → fall back
    // to the peer, which itself is a trusted proxy. Treat it as the client of
    // last resort; the allow-list will decide if it's permitted.
    Some(peer_ip)
}

pub struct IpAllowListMiddleware {
    allow_list: IpAllowList,
    trusted: TrustedProxies,
}

impl IpAllowListMiddleware {
    pub fn new(allow_list: IpAllowList, trusted: TrustedProxies) -> Self {
        Self {
            allow_list,
            trusted,
        }
    }
}

#[async_trait::async_trait]
impl Middleware for IpAllowListMiddleware {
    fn name(&self) -> &'static str {
        "ip-allow-list"
    }

    async fn on_request(&self, ctx: &mut RequestCtx, req: &mut Request<Body>) -> Flow {
        match resolve_client_ip(req, ctx, &self.trusted) {
            Some(ip) if self.allow_list.allows(ip) => {
                debug!("ip_allow_list: allowed {} to {}", ip, ctx.host);
                Flow::Continue
            }
            Some(ip) => {
                warn!("ip_allow_list: denied {} to {}", ip, ctx.host);
                Flow::ShortCircuit(diag::ip_forbidden(&ctx.host))
            }
            None => {
                // No resolvable client IP — fail closed. The whole point of
                // an allow-list is to gate on identity; without one we deny.
                warn!(
                    "ip_allow_list: no resolvable client IP for {}, denied",
                    ctx.host
                );
                Flow::ShortCircuit(diag::ip_forbidden(&ctx.host))
            }
        }
    }
}

/// Parse a list of "IP or CIDR" strings into `IpNet`. Logs and drops invalid
/// entries; bare IPs are promoted to host networks (/32 or /128). Used for
/// both the allow-list and `trusted_proxies`.
fn parse_cidrs(entries: &[String], label: &str) -> Vec<IpNet> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed = if trimmed.contains('/') {
            IpNet::from_str(trimmed).ok()
        } else {
            IpAddr::from_str(trimmed).ok().map(IpNet::from)
        };
        match parsed {
            Some(net) => out.push(net),
            None => warn!("{label}: invalid IP/CIDR '{entry}', ignored"),
        }
    }
    out
}

/// Collapse IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) to their IPv4
/// equivalent so an allow-list rule of `1.2.3.4` matches a client that
/// arrived over an IPv6 socket holding the same address. Without this the
/// allow-list silently misses legitimate clients on dual-stack systems.
fn unmap_ipv4(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    fn ctx(peer: Option<&str>) -> RequestCtx {
        RequestCtx {
            host: "example.com".to_string(),
            client_addr: peer.map(|p| SocketAddr::new(ip(p), 12345)),
            is_tls: false,
            client_encoding: None,
            pending_response_headers: Vec::new(),
        }
    }

    fn req(xff: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().uri("/");
        if let Some(v) = xff {
            b = b.header("x-forwarded-for", v);
        }
        b.body(Body::empty()).unwrap()
    }

    // ---- IpAllowList: core matching --------------------------------------

    #[test]
    fn bare_ip_matches_only_itself() {
        let list = IpAllowList::new(&["10.0.0.1".to_string()]);
        assert!(list.allows(ip("10.0.0.1")));
        assert!(!list.allows(ip("10.0.0.2")));
    }

    #[test]
    fn cidr_matches_range() {
        let list = IpAllowList::new(&["10.0.0.0/24".to_string()]);
        assert!(list.allows(ip("10.0.0.1")));
        assert!(list.allows(ip("10.0.0.254")));
        assert!(!list.allows(ip("10.0.1.1")));
    }

    #[test]
    fn ipv6_cidr() {
        let list = IpAllowList::new(&["2001:db8::/32".to_string()]);
        assert!(list.allows(ip("2001:db8::1")));
        assert!(!list.allows(ip("2001:dead::1")));
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_ipv4_rule() {
        // A client arriving on a dual-stack IPv6 socket holding the IPv4
        // mapping must match a plain IPv4 allow-list entry.
        let list = IpAllowList::new(&["10.0.0.5".to_string()]);
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped());
        assert!(list.allows(mapped));
    }

    #[test]
    fn invalid_entries_are_dropped_not_widened() {
        let list = IpAllowList::new(&["not-an-ip".to_string(), "10.0.0.1".to_string()]);
        assert!(list.allows(ip("10.0.0.1")));
        assert!(!list.allows(ip("10.0.0.2")));
    }

    #[test]
    fn all_invalid_yields_empty() {
        let list = IpAllowList::new(&["nope".to_string(), "10.0.0.0/99".to_string()]);
        assert!(list.is_empty());
    }

    // ---- Client-IP resolution: the trust model ---------------------------

    #[test]
    fn no_trusted_proxies_ignores_xff_entirely() {
        // Default deployment: XFF is *never* believed, even if the TCP peer
        // is a fellow proxy. Otherwise an attacker on the public side spoofs
        // their way past any allow-list.
        let trusted = TrustedProxies::default();
        let r = req(Some("10.0.0.1, 10.0.0.2"));
        let c = ctx(Some("198.51.100.7"));
        assert_eq!(
            resolve_client_ip(&r, &c, &trusted),
            Some(ip("198.51.100.7"))
        );
    }

    #[test]
    fn untrusted_peer_xff_is_dropped() {
        // Trusted proxies are configured, but the TCP peer isn't one of them
        // → we still ignore XFF and take the peer.
        let trusted = TrustedProxies::new(&["10.0.0.0/8".to_string()]);
        let r = req(Some("10.99.99.99"));
        let c = ctx(Some("198.51.100.7"));
        assert_eq!(
            resolve_client_ip(&r, &c, &trusted),
            Some(ip("198.51.100.7"))
        );
    }

    #[test]
    fn trusted_peer_xff_rightmost_non_trusted_is_client() {
        // Chain: [client] -> [edge proxy 10.0.0.5] -> [internal proxy 10.0.0.6] -> sozune
        // XFF as written by the edge: "203.0.113.42, 10.0.0.5"
        // TCP peer at sozune is the internal proxy, which is trusted.
        // Right-to-left walk skips 10.0.0.5 (trusted), keeps 203.0.113.42.
        let trusted = TrustedProxies::new(&["10.0.0.0/8".to_string()]);
        let r = req(Some("203.0.113.42, 10.0.0.5"));
        let c = ctx(Some("10.0.0.6"));
        assert_eq!(
            resolve_client_ip(&r, &c, &trusted),
            Some(ip("203.0.113.42"))
        );
    }

    #[test]
    fn trusted_peer_with_only_trusted_xff_falls_back_to_peer() {
        let trusted = TrustedProxies::new(&["10.0.0.0/8".to_string()]);
        let r = req(Some("10.0.0.1, 10.0.0.2"));
        let c = ctx(Some("10.0.0.6"));
        assert_eq!(resolve_client_ip(&r, &c, &trusted), Some(ip("10.0.0.6")));
    }

    #[test]
    fn trusted_peer_no_xff_uses_peer() {
        let trusted = TrustedProxies::new(&["10.0.0.0/8".to_string()]);
        let r = req(None);
        let c = ctx(Some("10.0.0.6"));
        assert_eq!(resolve_client_ip(&r, &c, &trusted), Some(ip("10.0.0.6")));
    }

    #[test]
    fn no_peer_no_xff_yields_none() {
        let trusted = TrustedProxies::default();
        let r = req(None);
        let c = ctx(None);
        assert_eq!(resolve_client_ip(&r, &c, &trusted), None);
    }

    // ---- End-to-end: the resolver feeds the allow-list -------------------

    #[test]
    fn xff_spoof_does_not_bypass_allow_list() {
        // Public attacker sends `X-Forwarded-For: 10.0.0.1` hoping to look
        // like an internal client. Without trusted_proxies, the peer (public
        // IP) is what the allow-list sees → 403.
        let trusted = TrustedProxies::default();
        let list = IpAllowList::new(&["10.0.0.0/8".to_string()]);
        let r = req(Some("10.0.0.1"));
        let c = ctx(Some("198.51.100.7"));
        let resolved = resolve_client_ip(&r, &c, &trusted).unwrap();
        assert!(!list.allows(resolved));
    }

    #[test]
    fn legitimate_xff_via_trusted_proxy_is_allowed() {
        let trusted = TrustedProxies::new(&["10.0.0.0/8".to_string()]);
        let list = IpAllowList::new(&["203.0.113.0/24".to_string()]);
        let r = req(Some("203.0.113.42, 10.0.0.5"));
        let c = ctx(Some("10.0.0.6"));
        let resolved = resolve_client_ip(&r, &c, &trusted).unwrap();
        assert!(list.allows(resolved));
    }

    // ---- IPv4-mapped IPv6 on the dual-stack peer side --------------------

    #[test]
    fn ipv4_mapped_peer_resolves_to_ipv4() {
        let trusted = TrustedProxies::default();
        let r = req(None);
        let peer = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped());
        let c = RequestCtx {
            host: "h".into(),
            client_addr: Some(SocketAddr::new(peer, 0)),
            is_tls: false,
            client_encoding: None,
            pending_response_headers: Vec::new(),
        };
        let list = IpAllowList::new(&["203.0.113.7".to_string()]);
        let resolved = resolve_client_ip(&r, &c, &trusted).unwrap();
        assert!(list.allows(resolved));
    }

    #[test]
    fn pure_ipv6_peer_does_not_collide_with_ipv4_rules() {
        let list = IpAllowList::new(&["10.0.0.5".to_string()]);
        assert!(!list.allows(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xa00, 5))));
    }
}
