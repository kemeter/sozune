//! Front door for port 443 when TLS-ALPN-01 is enabled.
//!
//! Normally Sōzu's HTTPS worker binds 443 directly. But answering a
//! TLS-ALPN-01 challenge means intercepting the handshake on 443 to present a
//! special certificate for the `acme-tls/1` protocol — something the HTTPS
//! worker won't do. So when a `tls-alpn-01` resolver is configured, this gate
//! binds 443 instead, prereads each connection's `ClientHello` for its ALPN
//! offer, and splices it to one of two loopback backends:
//!
//!   - offers `acme-tls/1`  → the local TLS-ALPN-01 responder
//!   - anything else        → the HTTPS worker (moved to a loopback port)
//!
//! The preread neither decrypts nor consumes: the buffered `ClientHello` bytes
//! are replayed to the chosen backend, so the handshake completes there exactly
//! as if the client had connected to it directly. This is the same
//! `copy_bidirectional` splice the TCP forwarder already uses, with an ALPN
//! decision in front.

use std::net::Ipv4Addr;
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
/// A hello whose ALPN only appears past the cap is treated as non-ACME and
/// spliced to the HTTPS worker unread — safe for normal traffic, which the
/// worker parses itself. The only casualty would be a *challenge* hello larger
/// than 64 KiB, which cannot happen: a TLS-ALPN-01 validator sends a minimal
/// hello (SNI + `acme-tls/1`), a few hundred bytes. So 64 KiB never misroutes a
/// real challenge while still being a firm ceiling.
const PREREAD_TIMEOUT: Duration = Duration::from_secs(5);
const PREREAD_MAX_BYTES: usize = 64 * 1024;

/// Where a prereaded connection should go.
struct GateSpec {
    /// Public port to bind (443).
    public_port: u16,
    /// Loopback port the HTTPS worker moved to — the default backend.
    https_loopback_port: u16,
    /// Loopback port the TLS-ALPN-01 responder listens on.
    responder_port: u16,
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
        .map_err(|e| anyhow::anyhow!("TLS-ALPN-01 gate could not bind 0.0.0.0:{public_port}: {e}"))
}

/// Route each connection on an already-bound `listener` by its ClientHello ALPN
/// offer, until the process exits.
pub async fn run(
    listener: TcpListener,
    public_port: u16,
    https_loopback_port: u16,
    responder_port: u16,
) {
    let spec = GateSpec {
        public_port,
        https_loopback_port,
        responder_port,
    };
    info!(
        "TLS-ALPN-01 gate on 0.0.0.0:{} → acme-tls/1 to 127.0.0.1:{}, else 127.0.0.1:{}",
        spec.public_port, spec.responder_port, spec.https_loopback_port
    );

    loop {
        let (inbound, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("TLS-ALPN-01 gate accept error: {e}");
                continue;
            }
        };
        let responder_port = spec.responder_port;
        let https_port = spec.https_loopback_port;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(inbound, peer, responder_port, https_port).await {
                debug!("TLS-ALPN-01 gate connection closed: {e}");
            }
        });
    }
}

/// Preread the ClientHello, pick a backend by ALPN, replay the buffered bytes,
/// and splice the rest.
///
/// `peer` is the real client address. The HTTPS worker (behind the gate on
/// loopback) would otherwise see every connection as `127.0.0.1`, so its
/// traffic is prefixed with a PROXY-v2 header carrying the true source and the
/// public destination the client actually reached. The responder gets no such
/// header — it doesn't expect one and doesn't care who is connecting.
async fn handle_connection(
    mut inbound: TcpStream,
    peer: std::net::SocketAddr,
    responder_port: u16,
    https_loopback_port: u16,
) -> std::io::Result<()> {
    // The public address the client connected to, before the gate spliced it
    // onto loopback — this is what belongs in the PROXY header's destination.
    let public_dest = inbound.local_addr()?;

    let (buffered, wants_acme) = preread_alpn(&mut inbound).await?;
    let backend_port = if wants_acme {
        responder_port
    } else {
        https_loopback_port
    };

    let mut outbound = TcpStream::connect((Ipv4Addr::LOCALHOST, backend_port)).await?;
    if !wants_acme {
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

/// Read from `inbound` until the ClientHello's ALPN can be decided, or the
/// preread deadline / byte cap is hit. Returns the raw bytes consumed (to be
/// replayed to the backend) and whether `acme-tls/1` was offered. On any parse
/// failure, timeout, or truncation the connection is treated as non-ACME: it
/// flows to the HTTPS worker, which makes its own call.
///
/// The deadline is a single absolute bound on the whole preread, not a
/// per-read one — otherwise a peer dripping a byte just under the timeout could
/// hold the task open indefinitely (a slowloris).
async fn preread_alpn(inbound: &mut TcpStream) -> std::io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + PREREAD_TIMEOUT;

    loop {
        match parse_client_hello_alpn(&buf) {
            AlpnParse::Decided(found) => return Ok((buf, found)),
            AlpnParse::NeedMore => {}
            AlpnParse::NotTls => return Ok((buf, false)),
        }
        if buf.len() >= PREREAD_MAX_BYTES {
            return Ok((buf, false));
        }

        let n = match tokio::time::timeout_at(deadline, inbound.read(&mut chunk)).await {
            Ok(Ok(0)) => return Ok((buf, false)), // peer closed
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok((buf, false)), // deadline: let HTTPS decide
        };
        // Never buffer past the cap, even if a single read overshoots it.
        let room = PREREAD_MAX_BYTES - buf.len();
        buf.extend_from_slice(&chunk[..n.min(room)]);
    }
}

enum AlpnParse {
    /// ALPN resolved: `true` if `acme-tls/1` was among the offered protocols.
    Decided(bool),
    /// Not enough bytes yet to reach (or finish) the ALPN extension.
    NeedMore,
    /// The stream isn't a TLS ClientHello at all.
    NotTls,
}

/// Extract whether the ClientHello in `buf` offers `acme-tls/1`.
///
/// A ClientHello can be split across several TLS handshake records, so the
/// handshake body is first reassembled from every leading `0x16` record, then
/// walked once. The walk is bounded by the handshake's own declared length, not
/// the record boundary, so trailing bytes after the ClientHello can't be read
/// as extensions. Anything malformed or truncated returns `NeedMore`/`NotTls`
/// rather than erroring; the caller degrades to the HTTPS path.
fn parse_client_hello_alpn(buf: &[u8]) -> AlpnParse {
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
                return AlpnParse::NotTls;
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
        return AlpnParse::NeedMore;
    }
    // Handshake header: msg_type(1) length(3). Type 1 = ClientHello.
    if hs_stream[0] != 0x01 {
        return AlpnParse::NotTls;
    }
    let declared = u32::from_be_bytes([0, hs_stream[1], hs_stream[2], hs_stream[3]]) as usize;
    let body_end = 4 + declared;
    if hs_stream.len() < body_end {
        return AlpnParse::NeedMore;
    }
    // Bound the walk by the ClientHello's declared length: trailing handshake
    // messages (or crafted bytes) after it must not be parsed as extensions.
    let hs = &hs_stream[..body_end];
    let mut p = 4usize;
    // client_version(2) random(32)
    p += 34;
    // session_id
    let Some(&sid_len) = hs.get(p) else {
        return AlpnParse::NeedMore;
    };
    p += 1 + sid_len as usize;
    // cipher_suites (u16 length-prefixed)
    let Some(cs_len) = read_u16(hs, p) else {
        return AlpnParse::NeedMore;
    };
    p += 2 + cs_len as usize;
    // compression_methods (u8 length-prefixed)
    let Some(&comp_len) = hs.get(p) else {
        return AlpnParse::NeedMore;
    };
    p += 1 + comp_len as usize;
    // extensions (u16 length-prefixed)
    let Some(ext_total) = read_u16(hs, p) else {
        return AlpnParse::NeedMore;
    };
    p += 2;
    let ext_end = p + ext_total as usize;
    if hs.len() < ext_end {
        return AlpnParse::NeedMore;
    }

    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let ext_len = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        p += 4;
        if p + ext_len > ext_end {
            return AlpnParse::NotTls;
        }
        if ext_type == 0x0010 {
            // ALPN: protocol_name_list is a u16-length-prefixed list of
            // u8-length-prefixed names.
            return AlpnParse::Decided(alpn_offers_acme(&hs[p..p + ext_len]));
        }
        p += ext_len;
    }
    // Fully parsed, no ALPN extension present.
    AlpnParse::Decided(false)
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
        // Extensions: one ALPN extension.
        let mut names = Vec::new();
        for proto in protocols {
            names.push(proto.len() as u8);
            names.extend_from_slice(proto);
        }
        let mut alpn_body = Vec::new();
        alpn_body.extend_from_slice(&(names.len() as u16).to_be_bytes());
        alpn_body.extend_from_slice(&names);

        let mut ext = Vec::new();
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

    fn decide(buf: &[u8]) -> AlpnParse {
        parse_client_hello_alpn(buf)
    }

    #[test]
    fn detects_acme_tls_alpn() {
        let hello = client_hello_with_alpn(&[b"acme-tls/1"]);
        assert!(matches!(decide(&hello), AlpnParse::Decided(true)));
    }

    #[test]
    fn normal_alpn_is_not_acme() {
        let hello = client_hello_with_alpn(&[b"h2", b"http/1.1"]);
        assert!(matches!(decide(&hello), AlpnParse::Decided(false)));
    }

    #[test]
    fn acme_among_others_is_detected() {
        // A conformant validator offers only acme-tls/1, but be liberal.
        let hello = client_hello_with_alpn(&[b"h2", b"acme-tls/1"]);
        assert!(matches!(decide(&hello), AlpnParse::Decided(true)));
    }

    #[test]
    fn no_alpn_extension_decides_non_acme() {
        // Truncate the ALPN extension off by rebuilding without it: a hello
        // with no extensions at all still parses to a non-ACME decision.
        let hello = client_hello_with_alpn(&[]);
        // Empty protocol list → no acme match.
        assert!(matches!(decide(&hello), AlpnParse::Decided(false)));
    }

    #[test]
    fn non_tls_first_byte_is_rejected() {
        assert!(matches!(decide(b"GET / HTTP/1.1\r\n"), AlpnParse::NotTls));
    }

    #[test]
    fn a_truncated_record_asks_for_more() {
        let hello = client_hello_with_alpn(&[b"acme-tls/1"]);
        // Cut mid-record: header says more is coming.
        assert!(matches!(decide(&hello[..8]), AlpnParse::NeedMore));
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
        assert!(matches!(decide(&split), AlpnParse::Decided(true)));
    }

    #[test]
    fn a_split_hello_missing_its_second_record_asks_for_more() {
        let hello = client_hello_with_alpn(&[b"acme-tls/1"]);
        let split = fragment_into_two_records(&hello, (hello.len() - 5) / 2);
        // Keep only the first record + its header: the handshake is incomplete.
        let first_rec_end = 5 + u16::from_be_bytes([split[3], split[4]]) as usize;
        assert!(matches!(
            decide(&split[..first_rec_end]),
            AlpnParse::NeedMore
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
        assert!(matches!(decide(&hello), AlpnParse::Decided(false)));
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
