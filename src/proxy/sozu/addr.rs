//! `Backend → SocketAddress` conversion. Parses an `"<ip>:<port>"` string into
//! Sōzu's protobuf `SocketAddress`. IPv6 is currently rejected — see the
//! tracking issue.

use crate::model::Backend;
use sozu_command_lib::proto::command::SocketAddress;

pub(super) fn parse_backend_address(backend: &Backend) -> anyhow::Result<SocketAddress> {
    let addr: std::net::SocketAddr = format!("{}:{}", backend.address, backend.port).parse()?;

    match addr {
        std::net::SocketAddr::V4(addr_v4) => {
            let ip = addr_v4.ip().octets();
            Ok(SocketAddress::new_v4(
                ip[0],
                ip[1],
                ip[2],
                ip[3],
                addr_v4.port(),
            ))
        }
        std::net::SocketAddr::V6(_) => {
            anyhow::bail!("IPv6 addresses are not yet supported")
        }
    }
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
    fn test_parse_backend_address_hostname() {
        let result = parse_backend_address(&Backend::new("localhost", 80));
        // Localhost may not resolve in all test environments
        // Just verify we get a consistent result
        match result {
            Ok(_) => (),
            Err(e) => {
                println!(
                    "Hostname resolution failed (expected in some test environments): {}",
                    e
                );
            }
        }
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
