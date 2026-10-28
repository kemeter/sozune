//! Front door for the HTTPS port when TLS-ALPN-01 or passthrough is enabled.
//!
//! Normally Sōzu's HTTPS worker binds 443 directly. Two things need a look at
//! the handshake before it: answering a TLS-ALPN-01 challenge, which means
//! presenting a special certificate for the `acme-tls/1` protocol, and TLS
//! passthrough on the HTTPS port (`proxy.https.passthrough`), which means
//! forwarding some connections undecrypted. The HTTPS worker does neither. So
//! when either is on, this gate binds the HTTPS port instead, prereads each
//! connection's `ClientHello` for its ALPN offer and its SNI, and splices it to
//! one of the loopback backends:
//!
//!   - offers `acme-tls/1`          → the local TLS-ALPN-01 responder
//!   - names a passthrough route    → the TCP listener serving those routes
//!   - anything else                → the HTTPS worker (moved to a loopback port)
//!
//! The preread neither decrypts nor consumes: the buffered `ClientHello` bytes
//! are replayed to the chosen backend, so the handshake completes there exactly
//! as if the client had connected to it directly. This is the same
//! `copy_bidirectional` splice the TCP forwarder already uses, with a decision
//! in front.

use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

/// `acme-tls/1`, the ALPN protocol a TLS-ALPN-01 validator offers.
const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// How long to wait for a `ClientHello` before giving up on a connection, and
/// how many wire bytes (record headers included) to buffer looking for it.
///
/// The cap bounds what a hostile peer can make the gate buffer per connection.
/// A hello not decided within the cap is spliced to the HTTPS worker unread —
/// safe for normal traffic, which the worker parses itself. A TLS-ALPN-01
/// validator sends a minimal hello (SNI + `acme-tls/1`), a few hundred bytes,
/// and clients put the SNI early in theirs, so 64 KiB never misroutes a real
/// one while still being a firm ceiling.
const PREREAD_TIMEOUT: Duration = Duration::from_secs(5);
pub const PREREAD_MAX_BYTES: usize = 64 * 1024;

/// The hostnames of the passthrough routes, as their SNI patterns: an exact
/// name, or `*.` and a suffix for one more label. Rewritten on every reload.
pub type PassthroughHosts = Arc<RwLock<Vec<String>>>;

/// The TCP listener serving the passthrough routes, behind the gate.
#[derive(Clone)]
pub struct Passthrough {
    /// Its loopback port.
    pub loopback_port: u16,
    /// The largest ClientHello it reads, in wire bytes.
    pub max_hello_bytes: usize,
    pub hosts: PassthroughHosts,
    /// The names of the certificates the HTTPS worker holds, as SNI
    /// patterns. A name neither they nor a passthrough route serve has its
    /// connection closed, as a TLSRoute listener must, rather than answered
    /// with Sōzu's default certificate.
    pub certificates: PassthroughHosts,
}

/// Where a prereaded connection may go.
#[derive(Clone)]
pub struct GateBackends {
    /// Loopback port the HTTPS worker moved to — the default backend.
    pub https_loopback_port: u16,
    /// Loopback port the TLS-ALPN-01 responder listens on, when enabled.
    pub responder_port: Option<u16>,
    /// The passthrough listener, when `proxy.https.passthrough` is on.
    pub passthrough: Option<Passthrough>,
}

/// Bind the public port for the gate, failing loudly if it's taken.
///
/// Bound synchronously at startup — separate from [`run`] — so a bind failure
/// (e.g. 443 already in use) aborts startup instead of leaving the process up
/// with no public HTTPS listener at all: the HTTPS worker has already stepped
/// onto loopback by this point, so a silent gate failure would black-hole 443.
pub async fn bind(public_port: u16) -> anyhow::Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::UNSPECIFIED, public_port))
        .await
        .map_err(|e| anyhow::anyhow!("TLS gate could not bind 0.0.0.0:{public_port}: {e}"))
}

/// Route each connection on an already-bound `listener` by its ClientHello,
/// until the process exits.
pub async fn run(listener: TcpListener, public_port: u16, backends: GateBackends) {
    info!(
        "TLS gate on 0.0.0.0:{} → HTTPS worker on 127.0.0.1:{}{}{}",
        public_port,
        backends.https_loopback_port,
        backends
            .responder_port
            .map(|p| format!(", acme-tls/1 to 127.0.0.1:{p}"))
            .unwrap_or_default(),
        backends
            .passthrough
            .as_ref()
            .map(|p| format!(", passthrough to 127.0.0.1:{}", p.loopback_port))
            .unwrap_or_default(),
    );

    loop {
        let (inbound, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("TLS gate accept error: {e}");
                continue;
            }
        };
        let backends = backends.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(inbound, peer, &backends).await {
                debug!("TLS gate connection closed: {e}");
            }
        });
    }
}

/// Preread the ClientHello, pick a backend, replay the buffered bytes, and
/// splice the rest.
///
/// `peer` is the real client address. The HTTPS worker (behind the gate on
/// loopback) would otherwise see every connection as `127.0.0.1`, so its
/// traffic is prefixed with a PROXY-v2 header carrying the true source and the
/// public destination the client actually reached. The responder and the
/// passthrough listener get no such header: they do not expect one.
async fn handle_connection(
    mut inbound: TcpStream,
    peer: std::net::SocketAddr,
    backends: &GateBackends,
) -> std::io::Result<()> {
    // The public address the client connected to, before the gate spliced it
    // onto loopback — this is what belongs in the PROXY header's destination.
    let public_dest = inbound.local_addr()?;

    let (buffered, hello) = preread_client_hello(&mut inbound).await?;
    let backend = pick_backend(&hello, backends);
    let backend_port = match backend {
        Backend::Responder(port) => port,
        Backend::Passthrough(port) => {
            // Too large for the passthrough listener to read: it would drop
            // it, after a connection to nowhere.
            if backends
                .passthrough
                .as_ref()
                .is_some_and(|p| buffered.len() > p.max_hello_bytes)
            {
                debug!(
                    "TLS gate: a {}-byte ClientHello is too large for the passthrough listener, closing",
                    buffered.len()
                );
                return Ok(());
            }
            port
        }
        Backend::Https => backends.https_loopback_port,
        Backend::Refused => {
            debug!("TLS gate: no route or certificate serves the SNI, closing");
            return Ok(());
        }
    };

    let mut outbound = TcpStream::connect((Ipv4Addr::LOCALHOST, backend_port)).await?;
    if backend == Backend::Https {
        // Preserve the client IP for the HTTPS worker, which is configured to
        // expect this header (`with_expect_proxy`).
        outbound
            .write_all(&proxy_v2_header(peer, public_dest))
            .await?;
    }
    // Replay the bytes consumed during preread, so the backend sees the whole
    // ClientHello from its first byte.
    if !buffered.is_empty() {
        outbound.write_all(&buffered).await?;
    }
    copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

/// The backend a connection is spliced to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Responder(u16),
    Passthrough(u16),
    Https,
    /// Served by nothing: the connection is closed.
    Refused,
}

/// Where a connection whose ClientHello says `hello` goes: an ACME challenge
/// to the responder, a name a passthrough route serves to the passthrough
/// listener, a name no certificate covers either nowhere, anything else — no
/// hello at all included — to the HTTPS worker.
fn pick_backend(hello: &ClientHello, backends: &GateBackends) -> Backend {
    if hello.acme
        && let Some(port) = backends.responder_port
    {
        return Backend::Responder(port);
    }
    if let (Some(sni), Some(passthrough)) = (hello.sni.as_deref(), &backends.passthrough) {
        // A poisoned lock leaves the connection to the HTTPS worker.
        let served = passthrough
            .hosts
            .read()
            .is_ok_and(|hosts| hosts.iter().any(|pattern| sni_matches(pattern, sni)));
        if served {
            return Backend::Passthrough(passthrough.loopback_port);
        }
        // A poisoned lock leaves the connection to the HTTPS worker too.
        let certified = passthrough.certificates.read().map_or(true, |names| {
            names.iter().any(|pattern| sni_matches(pattern, sni))
        });
        if !certified {
            return Backend::Refused;
        }
    }
    Backend::Https
}

/// Whether the SNI pattern `pattern` takes `sni`, as Sōzu's TCP listener does:
/// an exact name, or `*.` and a suffix for one more label, case aside.
pub(crate) fn sni_matches(pattern: &str, sni: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => sni
            .len()
            .checked_sub(suffix.len() + 1)
            .filter(|&split| split > 0)
            .is_some_and(|split| {
                sni.as_bytes()[split] == b'.'
                    && sni[split + 1..].eq_ignore_ascii_case(suffix)
                    && !sni[..split].contains('.')
            }),
        None => pattern.eq_ignore_ascii_case(sni),
    }
}

/// Build a PROXY protocol v2 header for a `source` → `destination` TCP
/// connection (RFC by HAProxy). Only the two address families Sōzune binds are
/// emitted; a mixed-family pair can't occur here (both ends are the same
/// socket's view), so it isn't handled.
fn proxy_v2_header(source: std::net::SocketAddr, dest: std::net::SocketAddr) -> Vec<u8> {
    use std::net::SocketAddr;

    // 12-byte signature, then version+command (0x21 = v2, PROXY), then the
    // transport+family byte, then a u16 address-block length.
    let mut h: Vec<u8> = vec![
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    h.push(0x21);
    match (source, dest) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            h.push(0x11); // AF_INET + STREAM
            h.extend_from_slice(&12u16.to_be_bytes());
            h.extend_from_slice(&s.ip().octets());
            h.extend_from_slice(&d.ip().octets());
            h.extend_from_slice(&s.port().to_be_bytes());
            h.extend_from_slice(&d.port().to_be_bytes());
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            h.push(0x21); // AF_INET6 + STREAM
            h.extend_from_slice(&36u16.to_be_bytes());
            h.extend_from_slice(&s.ip().octets());
            h.extend_from_slice(&d.ip().octets());
            h.extend_from_slice(&s.port().to_be_bytes());
            h.extend_from_slice(&d.port().to_be_bytes());
        }
        _ => {
            // Mixed families: emit LOCAL (0x20) with no addresses so the worker
            // still parses a valid header rather than the raw bytes.
            h[12] = 0x20;
            h.push(0x00);
            h.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    h
}

/// What the gate reads in a ClientHello.
#[derive(Debug, Default, PartialEq, Eq)]
struct ClientHello {
    /// Whether `acme-tls/1` is among the ALPN protocols offered.
    acme: bool,
    /// The host name of the `server_name` extension, if any.
    sni: Option<String>,
}

/// Read from `inbound` until the ClientHello can be decided, or the preread
/// deadline / byte cap is hit. Returns the raw bytes consumed (to be replayed
/// to the backend) and what the hello says. On any parse failure, timeout, or
/// truncation the connection gets an empty one: it flows to the HTTPS worker,
/// which makes its own call.
///
/// The deadline is a single absolute bound on the whole preread, not a
/// per-read one — otherwise a peer dripping a byte just under the timeout could
/// hold the task open indefinitely (a slowloris).
async fn preread_client_hello(inbound: &mut TcpStream) -> std::io::Result<(Vec<u8>, ClientHello)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + PREREAD_TIMEOUT;

    loop {
        match parse_client_hello(&buf) {
            HelloParse::Decided(hello) => return Ok((buf, hello)),
            HelloParse::NeedMore => {}
            HelloParse::NotTls => return Ok((buf, ClientHello::default())),
        }
        if buf.len() >= PREREAD_MAX_BYTES {
            return Ok((buf, ClientHello::default()));
        }

        let n = match tokio::time::timeout_at(deadline, inbound.read(&mut chunk)).await {
            Ok(Ok(0)) => return Ok((buf, ClientHello::default())), // peer closed
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            // Deadline: let HTTPS decide.
            Err(_) => return Ok((buf, ClientHello::default())),
        };
        // Never buffer past the cap, even if a single read overshoots it.
        let room = PREREAD_MAX_BYTES - buf.len();
        buf.extend_from_slice(&chunk[..n.min(room)]);
    }
}

enum HelloParse {
    /// The whole ClientHello was read.
    Decided(ClientHello),
    /// Not enough bytes yet to reach (or finish) the ClientHello.
    NeedMore,
    /// The stream isn't a TLS ClientHello at all.
    NotTls,
}

/// Read the ALPN offer and the SNI of the ClientHello in `buf`.
///
/// A ClientHello can be split across several TLS handshake records, so the
/// handshake body is first reassembled from every leading `0x16` record, then
/// walked once. The walk is bounded by the handshake's own declared length, not
/// the record boundary, so trailing bytes after the ClientHello can't be read
/// as extensions. Anything malformed or truncated returns `NeedMore`/`NotTls`
/// rather than erroring; the caller degrades to the HTTPS path.
fn parse_client_hello(buf: &[u8]) -> HelloParse {
    // Reassemble the handshake stream from consecutive handshake records.
    let mut hs_stream: Vec<u8> = Vec::new();
    let mut r = 0usize;
    loop {
        if buf.len() < r + 5 {
            // Header incomplete: need more, unless we've already got a
            // complete ClientHello reassembled below.
            break;
        }
        if buf[r] != 0x16 {
            // A non-handshake record interrupting the ClientHello: this isn't
            // the plain TLS-ALPN validator flow.
            if r == 0 {
                return HelloParse::NotTls;
            }
            break;
        }
        let rec_len = u16::from_be_bytes([buf[r + 3], buf[r + 4]]) as usize;
        let rec_end = r + 5 + rec_len;
        if buf.len() < rec_end {
            hs_stream.extend_from_slice(&buf[r + 5..]); // partial tail
            break;
        }
        hs_stream.extend_from_slice(&buf[r + 5..rec_end]);
        r = rec_end;
    }

    if hs_stream.len() < 4 {
        return HelloParse::NeedMore;
    }
    // Handshake header: msg_type(1) length(3). Type 1 = ClientHello.
    if hs_stream[0] != 0x01 {
        return HelloParse::NotTls;
    }
    let declared = u32::from_be_bytes([0, hs_stream[1], hs_stream[2], hs_stream[3]]) as usize;
    let body_end = 4 + declared;
    if hs_stream.len() < body_end {
        return HelloParse::NeedMore;
    }
    // Bound the walk by the ClientHello's declared length: trailing handshake
    // messages (or crafted bytes) after it must not be parsed as extensions.
    let hs = &hs_stream[..body_end];
    let mut p = 4usize;
    // client_version(2) random(32)
    p += 34;
    // session_id
    let Some(&sid_len) = hs.get(p) else {
        return HelloParse::NeedMore;
    };
    p += 1 + sid_len as usize;
    // cipher_suites (u16 length-prefixed)
    let Some(cs_len) = read_u16(hs, p) else {
        return HelloParse::NeedMore;
    };
    p += 2 + cs_len as usize;
    // compression_methods (u8 length-prefixed)
    let Some(&comp_len) = hs.get(p) else {
        return HelloParse::NeedMore;
    };
    p += 1 + comp_len as usize;
    // extensions (u16 length-prefixed)
    let Some(ext_total) = read_u16(hs, p) else {
        return HelloParse::NeedMore;
    };
    p += 2;
    let ext_end = p + ext_total as usize;
    if hs.len() < ext_end {
        return HelloParse::NeedMore;
    }

    let mut hello = ClientHello::default();
    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let ext_len = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        p += 4;
        if p + ext_len > ext_end {
            return HelloParse::NotTls;
        }
        match ext_type {
            // server_name.
            0x0000 => hello.sni = server_name(&hs[p..p + ext_len]),
            // ALPN: protocol_name_list is a u16-length-prefixed list of
            // u8-length-prefixed names.
            0x0010 => hello.acme = alpn_offers_acme(&hs[p..p + ext_len]),
            _ => {}
        }
        p += ext_len;
    }
    HelloParse::Decided(hello)
}

/// The host name of a `server_name` extension body: a u16-length-prefixed
/// list of entries, each a type byte (`0`, host name) and a u16-length-prefixed
/// name. `None` when it names no host, or one that is not a name.
fn server_name(ext: &[u8]) -> Option<String> {
    let list_len = read_u16(ext, 0)? as usize;
    let end = (2 + list_len).min(ext.len());
    let mut p = 2;
    while p + 3 <= end {
        let name_type = ext[p];
        let name_len = read_u16(ext, p + 1)? as usize;
        p += 3;
        let name = ext.get(p..p + name_len)?;
        if name_type == 0 {
            return std::str::from_utf8(name)
                .ok()
                .filter(|n| n.is_ascii())
                .map(str::to_ascii_lowercase);
        }
        p += name_len;
    }
    None
}

/// True if the ALPN extension body offers `acme-tls/1`.
fn alpn_offers_acme(ext: &[u8]) -> bool {
    // list_len(2), then repeated: name_len(1) name.
    if ext.len() < 2 {
        return false;
    }
    let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
    let mut p = 2;
    let end = (2 + list_len).min(ext.len());
    while p < end {
        let name_len = ext[p] as usize;
        p += 1;
        if p + name_len > end {
            break;
        }
        if &ext[p..p + name_len] == ACME_TLS_ALPN {
            return true;
        }
        p += name_len;
    }
    false
}

fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.get(at)?, *buf.get(at + 1)?]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ClientHello record carrying the given ALPN protocols.
    fn client_hello_with_alpn(protocols: &[&[u8]]) -> Vec<u8> {
        client_hello(protocols, None)
    }

    /// Build a minimal ClientHello record carrying the given ALPN protocols,
    /// after a `server_name` extension naming `sni`.
    fn client_hello(protocols: &[&[u8]], sni: Option<&str>) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(sni) = sni {
            let mut entry = vec![0u8];
            entry.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            entry.extend_from_slice(sni.as_bytes());
            let mut body = (entry.len() as u16).to_be_bytes().to_vec();
            body.extend_from_slice(&entry);
            ext.extend_from_slice(&0x0000u16.to_be_bytes());
            ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
            ext.extend_from_slice(&body);
        }
        // Then one ALPN extension.
        let mut names = Vec::new();
        for proto in protocols {
            names.push(proto.len() as u8);
            names.extend_from_slice(proto);
        }
        let mut alpn_body = Vec::new();
        alpn_body.extend_from_slice(&(names.len() as u16).to_be_bytes());
        alpn_body.extend_from_slice(&names);

        ext.extend_from_slice(&0x0010u16.to_be_bytes());
        ext.extend_from_slice(&(alpn_body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&alpn_body);

        // Handshake body: version(2) random(32) sid(1=0) ciphers(2len+2) comp(1len+1) ext(2len+..)
        let mut hs = Vec::new();
        hs.extend_from_slice(&[0x03, 0x03]); // version
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session_id len
        hs.extend_from_slice(&2u16.to_be_bytes()); // cipher len
        hs.extend_from_slice(&[0x13, 0x01]); // one cipher
        hs.push(1); // compression len
        hs.push(0); // null compression
        hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ext);

        // Handshake header: type(1)=ClientHello, length(3)
        let mut handshake = Vec::new();
        handshake.push(0x01);
        let hl = hs.len();
        handshake.push((hl >> 16) as u8);
        handshake.push((hl >> 8) as u8);
        handshake.push(hl as u8);
        handshake.extend_from_slice(&hs);

        // Record header: type(1)=handshake, version(2), length(2)
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// Whether the hello in `buf`, when whole, offers `acme-tls/1`.
    fn decide(buf: &[u8]) -> Decision {
        match parse_client_hello(buf) {
            HelloParse::Decided(hello) => Decision::Decided(hello.acme),
            HelloParse::NeedMore => Decision::NeedMore,
            HelloParse::NotTls => Decision::NotTls,
        }
    }

    enum Decision {
        Decided(bool),
        NeedMore,
        NotTls,
    }

    #[test]
    fn detects_acme_tls_alpn() {
        let hello = client_hello_with_alpn(&[b"acme-tls/1"]);
        assert!(matches!(decide(&hello), Decision::Decided(true)));
    }

    #[test]
    fn normal_alpn_is_not_acme() {
        let hello = client_hello_with_alpn(&[b"h2", b"http/1.1"]);
        assert!(matches!(decide(&hello), Decision::Decided(false)));
    }

    #[test]
    fn acme_among_others_is_detected() {
        // A conformant validator offers only acme-tls/1, but be liberal.
        let hello = client_hello_with_alpn(&[b"h2", b"acme-tls/1"]);
        assert!(matches!(decide(&hello), Decision::Decided(true)));
    }

    #[test]
    fn no_alpn_extension_decides_non_acme() {
        // Truncate the ALPN extension off by rebuilding without it: a hello
        // with no extensions at all still parses to a non-ACME decision.
        let hello = client_hello_with_alpn(&[]);
        // Empty protocol list → no acme match.
        assert!(matches!(decide(&hello), Decision::Decided(false)));
    }

    #[test]
    fn non_tls_first_byte_is_rejected() {
        assert!(matches!(decide(b"GET / HTTP/1.1\r\n"), Decision::NotTls));
    }

    #[test]
    fn a_truncated_record_asks_for_more() {
        let hello = client_hello_with_alpn(&[b"acme-tls/1"]);
        // Cut mid-record: header says more is coming.
        assert!(matches!(decide(&hello[..8]), Decision::NeedMore));
    }

    /// Re-frame a single-record ClientHello into two handshake records, split
    /// at byte `at` of the handshake body.
    fn fragment_into_two_records(single: &[u8], at: usize) -> Vec<u8> {
        // Strip the original 5-byte record header to get the handshake bytes.
        let handshake = &single[5..];
        let (first, second) = handshake.split_at(at);
        let mut out = Vec::new();
        for part in [first, second] {
            out.push(0x16);
            out.extend_from_slice(&[0x03, 0x01]);
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    #[test]
    fn a_clienthello_split_across_two_records_is_reassembled() {
        // The bug Codex found: only the first record was inspected, so a hello
        // split before its ALPN extension was misrouted. Split it right in the
        // middle and confirm ALPN is still found.
        let hello = client_hello_with_alpn(&[b"acme-tls/1"]);
        let split = fragment_into_two_records(&hello, (hello.len() - 5) / 2);
        assert!(matches!(decide(&split), Decision::Decided(true)));
    }

    #[test]
    fn a_split_hello_missing_its_second_record_asks_for_more() {
        let hello = client_hello_with_alpn(&[b"acme-tls/1"]);
        let split = fragment_into_two_records(&hello, (hello.len() - 5) / 2);
        // Keep only the first record + its header: the handshake is incomplete.
        let first_rec_end = 5 + u16::from_be_bytes([split[3], split[4]]) as usize;
        assert!(matches!(
            decide(&split[..first_rec_end]),
            Decision::NeedMore
        ));
    }

    #[test]
    fn trailing_bytes_after_the_clienthello_are_not_parsed_as_extensions() {
        // A record carrying the ClientHello plus extra crafted handshake bytes
        // must be walked only to the declared ClientHello length, so the extras
        // can't forge an ALPN decision.
        let mut hello = client_hello_with_alpn(&[b"h2"]);
        // Append junk inside the record by growing the record length and adding
        // bytes after the handshake. The declared handshake length is unchanged,
        // so the walk must ignore them.
        let extra = vec![0xAAu8; 16];
        let new_rec_len = (u16::from_be_bytes([hello[3], hello[4]]) as usize + extra.len()) as u16;
        hello[3..5].copy_from_slice(&new_rec_len.to_be_bytes());
        hello.extend_from_slice(&extra);
        // Still decides on the real ALPN (h2), not confused by the trailing junk.
        assert!(matches!(decide(&hello), Decision::Decided(false)));
    }

    fn hello_of(buf: &[u8]) -> ClientHello {
        match parse_client_hello(buf) {
            HelloParse::Decided(hello) => hello,
            _ => panic!("undecided hello"),
        }
    }

    #[test]
    fn the_sni_is_read_along_with_the_alpn() {
        let hello = hello_of(&client_hello(&[b"h2"], Some("App.Example.com")));
        assert_eq!(hello.sni.as_deref(), Some("app.example.com"));
        assert!(!hello.acme);
        let challenge = hello_of(&client_hello(&[b"acme-tls/1"], Some("app.example.com")));
        assert!(challenge.acme);
        assert_eq!(hello_of(&client_hello(&[b"h2"], None)).sni, None);
    }

    #[test]
    fn a_wildcard_takes_one_label() {
        assert!(sni_matches("app.example.com", "APP.example.com"));
        assert!(!sni_matches("app.example.com", "www.app.example.com"));
        assert!(sni_matches("*.example.com", "app.example.com"));
        assert!(!sni_matches("*.example.com", "a.b.example.com"));
        assert!(!sni_matches("*.example.com", "example.com"));
        assert!(!sni_matches("*.example.com", ".example.com"));
        assert!(!sni_matches("*.example.com", "appexample.com"));
    }

    /// A challenge goes to the responder, a name a passthrough route serves
    /// to the passthrough listener, one no certificate covers nowhere,
    /// anything else to the HTTPS worker.
    #[test]
    fn a_connection_goes_to_the_backend_its_hello_names() {
        let backends = GateBackends {
            https_loopback_port: 1,
            responder_port: Some(2),
            passthrough: Some(Passthrough {
                loopback_port: 3,
                max_hello_bytes: PREREAD_MAX_BYTES,
                hosts: Arc::new(RwLock::new(vec!["*.pass.example.com".into()])),
                certificates: Arc::new(RwLock::new(vec!["app.example.com".into()])),
            }),
        };
        let pick = |acme, sni: Option<&str>| {
            pick_backend(
                &ClientHello {
                    acme,
                    sni: sni.map(str::to_string),
                },
                &backends,
            )
        };
        assert_eq!(
            pick(true, Some("a.pass.example.com")),
            Backend::Responder(2)
        );
        assert_eq!(
            pick(false, Some("a.pass.example.com")),
            Backend::Passthrough(3)
        );
        assert_eq!(pick(false, Some("app.example.com")), Backend::Https);
        assert_eq!(pick(false, Some("other.example.com")), Backend::Refused);
        assert_eq!(pick(false, None), Backend::Https);

        let without = GateBackends {
            responder_port: None,
            passthrough: None,
            ..backends.clone()
        };
        let hello = ClientHello {
            acme: true,
            sni: Some("a.pass.example.com".into()),
        };
        assert_eq!(pick_backend(&hello, &without), Backend::Https);
    }

    #[test]
    fn proxy_v2_header_encodes_ipv4_addresses() {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 51000));
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443));
        let h = proxy_v2_header(src, dst);

        // Signature + v2/PROXY + INET/STREAM + 12-byte address block.
        assert_eq!(
            &h[..12],
            &[
                0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
            ]
        );
        assert_eq!(h[12], 0x21);
        assert_eq!(h[13], 0x11);
        assert_eq!(u16::from_be_bytes([h[14], h[15]]), 12);
        assert_eq!(&h[16..20], &[203, 0, 113, 7]); // source IP
        assert_eq!(&h[20..24], &[127, 0, 0, 1]); // dest IP
        assert_eq!(u16::from_be_bytes([h[24], h[25]]), 51000); // source port
        assert_eq!(u16::from_be_bytes([h[26], h[27]]), 443); // dest port
        assert_eq!(h.len(), 28);
    }
}
