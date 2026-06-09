//! Worker bootstrap.
//!
//! Sōzu only exposes its single-listener worker entry points under
//! `sozu_lib::{tcp,http,https}::testing::start_*_worker` — functions its own
//! rustdoc flags as "not used by Sōzu, available for example and testing
//! purposes". We run them in production, which is fragile (a `testing::` path
//! carries no stability guarantee) and, crucially, has **no UDP equivalent at
//! all** (`start_udp_worker` does not exist upstream).
//!
//! This module reassembles those bootstraps from Sōzu's *public* primitives
//! (`prebuild_server`, `Server::new`, the per-protocol `Proxy`s) so we no longer
//! call the `start_*_worker` helpers, and so we can start a UDP worker — which
//! Sōzu supports internally (`Server::new` always builds a `UdpProxy`) but never
//! exposed a launcher for.
//!
//! Each `start_*_worker` mirrors the upstream helper one-for-one for HTTP/HTTPS/
//! TCP; `start_udp_worker` is new (see its doc for why it is shaped differently).

use sozu_command_lib::proto::command::{
    HttpListenerConfig, HttpsListenerConfig, TcpListenerConfig,
};
use sozu_lib::testing::{
    Context, ListenSession, Protocol, ProxyChannel, Rc, RefCell, Server, ServerParts, Token,
    prebuild_server,
};
use sozu_lib::{http::HttpProxy, https::HttpsProxy, tcp::TcpProxy};

/// Insert a `ListenSession` of the given protocol into the server's slab and
/// return its token. Every listener needs this slab entry before its proxy can
/// `add_listener`/`activate_listener` against it.
fn reserve_listen_token(server_parts: &ServerParts, protocol: Protocol) -> Token {
    let mut sessions = server_parts.sessions.borrow_mut();
    let entry = sessions.slab.vacant_entry();
    let key = entry.key();
    let _ = entry.insert(Rc::new(RefCell::new(ListenSession { protocol })));
    Token(key)
}

/// Start a single Sōzu HTTP worker on `config`'s address, driven by `channel`.
///
/// Reassembled from `sozu_lib::http::testing::start_http_worker` using only
/// public primitives. Blocks on the event loop until the worker stops.
pub fn start_http_worker(
    config: HttpListenerConfig,
    channel: ProxyChannel,
    max_buffers: usize,
    buffer_size: usize,
) -> anyhow::Result<()> {
    let address = config.address.into();
    let parts = prebuild_server(max_buffers, buffer_size, true)?;
    let token = reserve_listen_token(&parts, Protocol::HTTPListen);

    let ServerParts {
        event_loop,
        registry,
        sessions,
        pool,
        backends,
        server_scm_socket,
        server_config,
        ..
    } = parts;

    let mut proxy = HttpProxy::new(registry, sessions.clone(), pool.clone(), backends.clone());
    proxy
        .add_listener(config, token)
        .with_context(|| "Failed at adding the HTTP listener")?;
    proxy
        .activate_listener(&address, None)
        .with_context(|| "Failed at activating the HTTP listener")?;

    let mut server = Server::new(
        event_loop,
        channel,
        server_scm_socket,
        sessions,
        pool,
        backends,
        Some(proxy),
        None,
        None,
        server_config,
        None,
        false,
    )
    .with_context(|| "Failed at creating the HTTP server")?;
    server.run();
    Ok(())
}

/// Start a single Sōzu HTTPS worker on `config`'s address, driven by `channel`.
///
/// Reassembled from `sozu_lib::https::testing::start_https_worker` using only
/// public primitives. Blocks on the event loop until the worker stops.
pub fn start_https_worker(
    config: HttpsListenerConfig,
    channel: ProxyChannel,
    max_buffers: usize,
    buffer_size: usize,
) -> anyhow::Result<()> {
    let address = config.address.into();
    let parts = prebuild_server(max_buffers, buffer_size, true)?;
    let token = reserve_listen_token(&parts, Protocol::HTTPSListen);

    let ServerParts {
        event_loop,
        registry,
        sessions,
        pool,
        backends,
        server_scm_socket,
        server_config,
        ..
    } = parts;

    let mut proxy = HttpsProxy::new(registry, sessions.clone(), pool.clone(), backends.clone());
    proxy
        .add_listener(config, token)
        .with_context(|| "Failed at adding the HTTPS listener")?;
    proxy
        .activate_listener(&address, None)
        .with_context(|| "Failed at activating the HTTPS listener")?;

    let mut server = Server::new(
        event_loop,
        channel,
        server_scm_socket,
        sessions,
        pool,
        backends,
        None,
        Some(proxy),
        None,
        server_config,
        None,
        false,
    )
    .with_context(|| "Failed at creating the HTTPS server")?;
    server.run();
    Ok(())
}

/// Start a single Sōzu TCP worker on `config`'s address, driven by `channel`.
///
/// Reassembled from `sozu_lib::tcp::testing::start_tcp_worker` using only public
/// primitives. Blocks on the event loop until the worker stops.
pub fn start_tcp_worker(
    config: TcpListenerConfig,
    max_buffers: usize,
    buffer_size: usize,
    channel: ProxyChannel,
) -> anyhow::Result<()> {
    let address = config.address.into();
    let parts = prebuild_server(max_buffers, buffer_size, true)?;
    let token = reserve_listen_token(&parts, Protocol::TCPListen);

    let ServerParts {
        event_loop,
        registry,
        sessions,
        pool,
        backends,
        server_scm_socket,
        server_config,
        ..
    } = parts;

    let mut proxy = TcpProxy::new(registry, sessions.clone(), pool.clone(), backends.clone());
    proxy
        .add_listener(config, token)
        .with_context(|| "Failed at adding the TCP listener")?;
    proxy
        .activate_listener(&address, None)
        .with_context(|| "Failed at activating the TCP listener")?;

    let mut server = Server::new(
        event_loop,
        channel,
        server_scm_socket,
        sessions,
        pool,
        backends,
        None,
        None,
        Some(proxy),
        server_config,
        None,
        false,
    )
    .with_context(|| "Failed at creating the TCP server")?;
    server.run();
    Ok(())
}

/// Start a single Sōzu UDP worker, driven by `channel`.
///
/// **Shaped differently from the TCP/HTTP/HTTPS workers**, and on purpose: Sōzu
/// has no `start_udp_worker` and no way to pass a `UdpProxy` into `Server::new`
/// — the server always builds its own `UdpProxy` internally. So unlike the other
/// three, this worker takes **no listener config to pre-activate**: it starts a
/// bare UDP-capable `Server` and the listener is installed later, the same way
/// Sōzu does natively, by sending `AddUdpListener` + `ActivateListener` over the
/// `channel` (wired from `spawn_udp_workers`). Blocks on the event loop until stop.
pub fn start_udp_worker(
    channel: ProxyChannel,
    max_buffers: usize,
    buffer_size: usize,
) -> anyhow::Result<()> {
    let ServerParts {
        event_loop,
        registry: _,
        sessions,
        pool,
        backends,
        server_scm_socket,
        server_config,
        ..
    } = prebuild_server(max_buffers, buffer_size, true)?;

    // No proxy argument: `Server::new` constructs the `UdpProxy` itself. The UDP
    // listener is added/activated afterwards via channel requests.
    let mut server = Server::new(
        event_loop,
        channel,
        server_scm_socket,
        sessions,
        pool,
        backends,
        None,
        None,
        None,
        server_config,
        None,
        false,
    )
    .with_context(|| "Failed at creating the UDP server")?;
    server.run();
    Ok(())
}
