//! `Backend → SocketAddress` conversion. Parses an `"<ip>:<port>"` string into
//! Sōzu's protobuf `SocketAddress`. Both IPv4 and IPv6 are accepted — IPv6
//! addresses in the input must be bracketed (`[::1]:80`) per RFC 3986 so the
//! `host:port` split is unambiguous.

use crate::model::Backend;
use sozu_command_lib::proto::command::SocketAddress;

pub(super) fn parse_backend_address(backend: &Backend) -> anyhow::Result<SocketAddress> {
    // Bracket bare IPv6 literals so `<addr>:<port>` parses correctly. IPv4
    // addresses and bracketed IPv6 already round-trip through `<addr>:<port>`.
    let host_port = if backend.address.contains(':') && !backend.address.starts_with('[') {
        format!("[{}]:{}", backend.address, backend.port)
    } else {
        format!("{}:{}", backend.address, backend.port)
    };
    let addr: std::net::SocketAddr = host_port.parse()?;
    Ok(SocketAddress::from(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_backend_address_ipv4() {
        let result = parse_backend_address(&Backend::new("192.168.1.100", 8080));
        assert!(result.is_ok(), "Failed to parse IPv4 address: {:?}", result);
    }

    #[test]
    fn test_parse_backend_address_localhost() {
        let result = parse_backend_address(&Backend::new("127.0.0.1", 3000));
        assert!(result.is_ok(), "Failed to parse localhost: {:?}", result);
    }

    #[test]
    fn test_parse_backend_address_hostname_rejected() {
        // Hostnames are not socket addresses — only IP literals are accepted.
        // Sōzune resolves DNS at the provider layer, never here.
        let result = parse_backend_address(&Backend::new("localhost", 80));
        assert!(
            result.is_err(),
            "hostname must be rejected; resolution belongs to the provider"
        );
    }

    #[test]
    fn test_parse_backend_address_ipv6() {
        // IPv6 literals are accepted unbracketed — we wrap them ourselves.
        let result = parse_backend_address(&Backend::new("::1", 8080));
        assert!(result.is_ok(), "Failed to parse IPv6 ::1: {:?}", result);
    }

    #[test]
    fn test_parse_backend_address_ipv6_full() {
        let result = parse_backend_address(&Backend::new("fd00::1234:5678", 443));
        assert!(
            result.is_ok(),
            "Failed to parse fd00::1234:5678: {:?}",
            result
        );
    }

    #[test]
    fn test_parse_backend_address_ipv6_bracketed() {
        // Already bracketed addresses must also be accepted, even though no
        // provider currently emits that form — defensive parsing.
        let result = parse_backend_address(&Backend::new("[2001:db8::1]", 9000));
        assert!(
            result.is_ok(),
            "Failed to parse bracketed IPv6: {:?}",
            result
        );
    }

    #[test]
    fn test_parse_backend_address_invalid() {
        let result =
            parse_backend_address(&Backend::new("invalid-host-name-that-does-not-exist", 80));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_backend_address_invalid_port() {
        let result = parse_backend_address(&Backend::new("127.0.0.1", 0));
        assert!(result.is_ok()); // Port 0 is technically valid
    }
}
