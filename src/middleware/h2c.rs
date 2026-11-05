//! HTTP/2 in cleartext with prior knowledge (h2c) to the backends that speak
//! it, as gRPC servers do.
//!
//! One connection per backend, shared by the requests sent to it: HTTP/2
//! multiplexes them, and the requests that find none open wait for the one
//! being made. The request keeps the authority the client asked for (its
//! `:authority`), rather than the backend's address the connection is made
//! to, so a backend telling virtual hosts apart by it sees the right one. A
//! connection closed, or unused for a while (its backend gone from the
//! routes, say), is let go.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, Response, Uri};
use hyper::body::Incoming;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::debug;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// How long a connection may go unused before it is let go.
const IDLE: Duration = Duration::from_secs(300);

/// The connection to one backend, with when it was last used and a number
/// telling it from those before it: `None` while there is none.
type Slot = Arc<tokio::sync::Mutex<Option<Held>>>;

struct Held {
    sender: SendRequest<Body>,
    used: Instant,
    generation: u64,
}

/// Tells each connection from the others.
static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The h2c connections to the backends, by address.
#[derive(Clone, Default)]
pub struct H2cPool {
    slots: Arc<Mutex<HashMap<(String, u16), Slot>>>,
}

impl H2cPool {
    /// Send `req` to `backend` over h2c, as `authority`.
    pub async fn send(
        &self,
        backend: &(String, u16),
        authority: &str,
        mut req: Request<Body>,
    ) -> Result<Response<Incoming>, BoxError> {
        let path = req
            .uri()
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_string();
        *req.uri_mut() = format!("http://{authority}{path}").parse::<Uri>()?;
        *req.version_mut() = axum::http::Version::HTTP_2;
        let mut sender = self.sender(backend).await?;
        sender.ready().await?;
        Ok(sender.send_request(req).await?)
    }

    /// The slot of `backend`.
    fn slot(&self, backend: &(String, u16)) -> Slot {
        match self.slots.lock() {
            Ok(mut slots) => slots.entry(backend.clone()).or_default().clone(),
            Err(_) => Slot::default(),
        }
    }

    /// The connection to `backend`: the one open, or a new one, made once
    /// for the requests waiting on it.
    async fn sender(&self, backend: &(String, u16)) -> Result<SendRequest<Body>, BoxError> {
        let slot = self.slot(backend);
        let mut held = slot.lock().await;
        if let Some(open) = held.as_mut()
            && !open.sender.is_closed()
        {
            open.used = Instant::now();
            return Ok(open.sender.clone());
        }
        // Left empty if the connection is not made, cancelled included.
        let mut forget = ForgetEmpty {
            pool: self.clone(),
            backend: backend.clone(),
            slot: slot.clone(),
            armed: true,
        };
        let stream = TcpStream::connect((backend.0.as_str(), backend.1)).await?;
        let _ = stream.set_nodelay(true);
        let (sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await?;
        forget.armed = false;
        let address = format!("{}:{}", backend.0, backend.1);
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!("h2c connection to {address} closed: {e}");
            }
        });
        let generation = GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *held = Some(Held {
            sender: sender.clone(),
            used: Instant::now(),
            generation,
        });
        drop(held);
        self.evict_when_unused(backend.clone(), slot, generation);
        Ok(sender)
    }

    /// Let connection `generation` of `slot` go once closed or idle, whether
    /// or not another request comes. Done once another took its place.
    fn evict_when_unused(&self, backend: (String, u16), slot: Slot, generation: u64) {
        let pool = self.clone();
        tokio::spawn(async move {
            loop {
                let next = {
                    let mut held = slot.lock().await;
                    match held.as_ref() {
                        // Another connection's to watch.
                        Some(open) if open.generation != generation => return,
                        Some(open) if !open.sender.is_closed() && open.used.elapsed() < IDLE => {
                            Some(open.used + IDLE)
                        }
                        _ => {
                            *held = None;
                            None
                        }
                    }
                };
                match next {
                    // Checked again at least once a second, to see a
                    // closed connection soon.
                    Some(at) => {
                        tokio::time::sleep_until(at.min(Instant::now() + Duration::from_secs(1)))
                            .await
                    }
                    None => break,
                }
            }
            pool.forget_if_empty(&backend, &slot);
        });
    }

    /// Drop the slot of `backend` if it is still `slot` and holds nothing:
    /// a request may have put a new connection in it meanwhile.
    fn forget_if_empty(&self, backend: &(String, u16), slot: &Slot) {
        if let Ok(mut slots) = self.slots.lock()
            && slots
                .get(backend)
                .is_some_and(|s| Arc::ptr_eq(s, slot) && s.try_lock().is_ok_and(|h| h.is_none()))
        {
            slots.remove(backend);
        }
    }

    #[cfg(test)]
    fn held(&self) -> usize {
        self.slots.lock().map_or(0, |s| s.len())
    }
}

/// Forgets the slot of a connection that was not made, once its lock is
/// released.
struct ForgetEmpty {
    pool: H2cPool,
    backend: (String, u16),
    slot: Slot,
    /// Cleared once the connection is made.
    armed: bool,
}

impl Drop for ForgetEmpty {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let (pool, backend, slot) = (self.pool.clone(), self.backend.clone(), self.slot.clone());
        // The slot's lock is still held here: let it go first.
        tokio::spawn(async move { pool.forget_if_empty(&backend, &slot) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend answering `200` on h2c, closing each connection after
    /// `lifetime`, and how many connections it took.
    async fn backend(lifetime: Duration) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = accepted.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(|_req: Request<Incoming>| async {
                        Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
                    });
                    let _ = tokio::time::timeout(
                        lifetime,
                        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(stream), service),
                    )
                    .await;
                });
            }
        });
        (port, accepted)
    }

    /// A connection its backend closed is let go without another request.
    #[tokio::test]
    async fn a_closed_connection_is_let_go() {
        let (port, _) = backend(Duration::from_millis(200)).await;
        let pool = H2cPool::default();
        let backend = ("127.0.0.1".to_string(), port);
        let response = pool
            .send(&backend, "app.test", Request::new(Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(pool.held(), 1);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(pool.held(), 0);
    }

    /// A backend that cannot be reached leaves no slot behind.
    #[tokio::test]
    async fn an_unreachable_backend_leaves_nothing() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let pool = H2cPool::default();
        let backend = ("127.0.0.1".to_string(), port);
        assert!(
            pool.send(&backend, "app.test", Request::new(Body::empty()))
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(pool.held(), 0);
    }

    /// Requests that find no connection share the one being made.
    #[tokio::test]
    async fn a_burst_shares_one_connection() {
        let (port, accepted) = backend(Duration::from_secs(5)).await;
        let pool = H2cPool::default();
        let backend = ("127.0.0.1".to_string(), port);
        let calls: Vec<_> = (0..10)
            .map(|_| {
                let pool = pool.clone();
                let backend = backend.clone();
                tokio::spawn(async move {
                    pool.send(&backend, "app.test", Request::new(Body::empty()))
                        .await
                        .map(|r| r.status())
                })
            })
            .collect();
        for call in calls {
            assert_eq!(call.await.unwrap().unwrap(), 200);
        }
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
