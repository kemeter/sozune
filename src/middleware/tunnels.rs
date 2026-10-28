//! The WebSocket tunnels the middleware holds open, so that those whose
//! backend leaves its route are closed, as Sōzu closes its own sessions: the
//! client reconnects to a backend that is still there.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use tokio::sync::oneshot;
use tracing::info;

/// One open tunnel: the route it was opened on, the backend at its other
/// end, and what closes it.
struct Tunnel {
    cluster_id: String,
    backend: (String, u16),
    /// Dropped to close the tunnel.
    _close: oneshot::Sender<()>,
}

#[derive(Default)]
struct State {
    open: HashMap<u64, Tunnel>,
    /// The backends of each HTTP route, as the last reload left them.
    routes: HashMap<String, Vec<(String, u16)>>,
    /// Those of the reload under way, which the middleware already routes
    /// to while it installs them.
    published: HashMap<String, Vec<(String, u16)>>,
}

impl State {
    fn current(&self, cluster_id: &str, backend: &(String, u16)) -> bool {
        [&self.routes, &self.published].iter().any(|routes| {
            routes
                .get(cluster_id)
                .is_some_and(|backends| backends.contains(backend))
        })
    }
}

#[derive(Default)]
pub struct Tunnels {
    next_id: AtomicU64,
    state: Mutex<State>,
}

/// The tunnels of the middleware server.
pub fn tunnels() -> &'static Tunnels {
    static TUNNELS: OnceLock<Tunnels> = OnceLock::new();
    TUNNELS.get_or_init(Tunnels::default)
}

/// A tunnel registered in [`Tunnels`], until it is dropped.
pub struct OpenTunnel<'a> {
    tunnels: &'a Tunnels,
    id: u64,
    closed: oneshot::Receiver<()>,
}

impl OpenTunnel<'_> {
    /// Resolves once the tunnel's backend has left its route.
    pub async fn closed(&mut self) {
        let _ = (&mut self.closed).await;
    }
}

impl Drop for OpenTunnel<'_> {
    fn drop(&mut self) {
        self.tunnels.state().open.remove(&self.id);
    }
}

impl Tunnels {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Registers a tunnel opened on `cluster_id` to `backend`, unless the
    /// backend has left that route since the handshake began.
    pub fn register(&self, cluster_id: &str, backend: (String, u16)) -> Option<OpenTunnel<'_>> {
        let mut state = self.state();
        if !state.current(cluster_id, &backend) {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (close, closed) = oneshot::channel();
        state.open.insert(
            id,
            Tunnel {
                cluster_id: cluster_id.to_string(),
                backend,
                _close: close,
            },
        );
        Some(OpenTunnel {
            tunnels: self,
            id,
            closed,
        })
    }

    /// Admits tunnels to `routes`, the backends of each HTTP route, which
    /// the middleware routes to from now on, until [`Self::reroute`] ends the
    /// reload.
    pub fn publish(&self, routes: HashMap<String, Vec<(String, u16)>>) {
        self.state().published = routes;
    }

    /// Takes `routes`, the backends of each HTTP route, and closes the
    /// tunnels to a backend their route no longer has, the route gone
    /// included. A route `waiting` names keeps the backends it had, and its
    /// tunnels with them.
    pub fn reroute(
        &self,
        routes: HashMap<String, Vec<(String, u16)>>,
        waiting: impl Fn(&str) -> bool,
    ) {
        let mut state = self.state();
        state.published.clear();
        let mut previous = std::mem::take(&mut state.routes);
        state.routes = routes;
        for (cluster_id, backends) in previous.drain() {
            if waiting(&cluster_id) {
                state.routes.insert(cluster_id, backends);
            }
        }
        let State { open, routes, .. } = &mut *state;
        let before = open.len();
        open.retain(|_, tunnel| {
            routes
                .get(&tunnel.cluster_id)
                .is_some_and(|backends| backends.contains(&tunnel.backend))
        });
        let closed = before - open.len();
        if closed > 0 {
            info!("Closed {closed} WebSocket tunnel(s) to backends that left their route");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(host: &str) -> (String, u16) {
        (host.to_string(), 80)
    }

    /// Route `web` over `b0` and `b1`.
    fn tunnels() -> Tunnels {
        let tunnels = Tunnels::default();
        tunnels.reroute(
            [("web".to_string(), vec![backend("b0"), backend("b1")])].into(),
            |_| false,
        );
        tunnels
    }

    #[tokio::test]
    async fn the_tunnels_to_a_departed_backend_are_closed() {
        let tunnels = tunnels();
        let mut departed = tunnels.register("web", backend("b0")).unwrap();
        let mut kept = tunnels.register("web", backend("b1")).unwrap();

        tunnels.reroute([("web".to_string(), vec![backend("b1")])].into(), |_| false);

        departed.closed().await;
        let still_open =
            tokio::time::timeout(std::time::Duration::from_millis(50), kept.closed()).await;
        assert!(still_open.is_err());
    }

    /// A route the reload left uninstalled keeps its tunnels, and they close
    /// once a later reload installs it.
    #[tokio::test]
    async fn a_waiting_route_keeps_its_tunnels() {
        let tunnels = tunnels();
        let mut tunnel = tunnels.register("web", backend("b0")).unwrap();

        tunnels.reroute(HashMap::new(), |cluster_id| cluster_id == "web");
        let still_open =
            tokio::time::timeout(std::time::Duration::from_millis(50), tunnel.closed()).await;
        assert!(still_open.is_err());

        tunnels.reroute(HashMap::new(), |_| false);
        tunnel.closed().await;
    }

    /// A backend the middleware routes to before the reload ends is admitted.
    #[test]
    fn a_published_backend_is_admitted() {
        let tunnels = tunnels();
        tunnels.publish([("web".to_string(), vec![backend("b2")])].into());
        assert!(tunnels.register("web", backend("b2")).is_some());
        assert!(tunnels.register("web", backend("b0")).is_some());
    }

    /// A handshake ending after the reload swept the tunnels finds the
    /// backend gone.
    #[test]
    fn a_backend_off_the_route_is_refused() {
        let tunnels = tunnels();
        assert!(tunnels.register("web", backend("b2")).is_none());
        assert!(tunnels.register("gone", backend("b0")).is_none());
        assert!(tunnels.state().open.is_empty());
    }

    #[test]
    fn a_closed_tunnel_leaves_the_registry() {
        let tunnels = tunnels();
        drop(tunnels.register("web", backend("b0")));
        assert!(tunnels.state().open.is_empty());
    }
}
