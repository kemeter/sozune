//! HTTP Basic auth for the management API.
//!
//! Mirrors the storage format Sozu uses for route-level basic auth so users
//! generate hashes the same way on both sides: `username:hex(sha256(password))`.
//! Comparison is constant-time over a fixed envelope so the time spent
//! validating a credential leaks neither the matching slot nor the matching
//! username length.

use crate::config::{ApiUser, Role};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Maximum size, in bytes, of a base64-decoded `Authorization: Basic`
/// payload. RFC 7617 imposes no limit but anything beyond this for a
/// management API is pathological.
const MAX_DECODED_CREDENTIAL_BYTES: usize = 4096;

/// Pad length used by [`constant_time_match`]. Must be at least as large as
/// the longest realistic `username:hex(sha256)` we ever compare. SHA-256 hex
/// is 64 chars; usernames are bounded in practice but we leave generous
/// headroom so a longer username does not bypass the constant-time guard.
const PAD_LEN: usize = 256;

/// Resolved identity attached to authenticated requests. Stored in
/// `request.extensions()` so handlers and logs can read it back.
#[derive(Debug, Clone)]
pub struct Identity {
    pub name: String,
    pub role: Role,
}

/// Outcome of validating an `Authorization` header against the user list.
pub enum AuthOutcome {
    /// No credential was present (no header, wrong scheme, malformed).
    Missing,
    /// Credential was well-formed but did not match any configured user.
    Invalid,
    /// Credential matched. The resolved identity is returned.
    Authenticated(Identity),
}

/// Verify a raw `Authorization` header value against the configured users.
pub fn check(header_value: Option<&str>, users: &[ApiUser]) -> AuthOutcome {
    let Some(value) = header_value else {
        return AuthOutcome::Missing;
    };

    let Some(decoded) = decode_basic(value) else {
        return AuthOutcome::Missing;
    };

    let Some((submitted_user, password)) = decoded.split_once(':') else {
        return AuthOutcome::Missing;
    };

    let submitted_hash = hex_sha256(password.as_bytes());
    let candidate = format!("{submitted_user}:{submitted_hash}");

    // Build the canonical entry list once so the comparison loop iterates
    // every user even on a hit.
    let entries: Vec<String> = users
        .iter()
        .map(|u| format!("{}:{}", u.name, u.hash))
        .collect();

    if !constant_time_match(&candidate, &entries) {
        return AuthOutcome::Invalid;
    }

    // Match found — locate the user (this lookup is fine to short-circuit;
    // the sensitive part is the credential check above).
    if let Some(user) = users.iter().find(|u| {
        let entry = format!("{}:{}", u.name, u.hash);
        entry == candidate
    }) {
        AuthOutcome::Authenticated(Identity {
            name: user.name.clone(),
            role: user.role,
        })
    } else {
        AuthOutcome::Invalid
    }
}

/// Decode a `Basic <token>` header value into the raw `user:password` UTF-8
/// string. Returns `None` for any malformed input.
fn decode_basic(value: &str) -> Option<String> {
    let trimmed = value.trim_start();
    let token = trimmed
        .strip_prefix("Basic ")
        .or_else(|| trimmed.strip_prefix("basic "))?;
    let decoded = STANDARD.decode(token.trim()).ok()?;
    if decoded.len() > MAX_DECODED_CREDENTIAL_BYTES {
        return None;
    }
    String::from_utf8(decoded).ok()
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Compare `candidate` against every entry using constant-time equality
/// over a fixed envelope. Both sides are padded to `PAD_LEN` plus a length
/// suffix before `subtle::ConstantTimeEq` runs, which:
///   * makes the per-entry compare iterate the full padded length even
///     when candidate and entry differ in length (subtle's slice `ct_eq`
///     short-circuits on length mismatch — padding defeats that leak);
///   * makes the outer loop iterate the full slice on every call, so the
///     time spent does not vary with the position of the matching entry.
fn constant_time_match(candidate: &str, entries: &[String]) -> bool {
    let candidate_padded = pad(candidate.as_bytes());
    let mut matched = subtle::Choice::from(0u8);
    for entry in entries {
        let entry_padded = pad(entry.as_bytes());
        matched |= candidate_padded.as_slice().ct_eq(entry_padded.as_slice());
    }
    bool::from(matched)
}

fn pad(input: &[u8]) -> [u8; PAD_LEN + 8] {
    let mut buf = [0u8; PAD_LEN + 8];
    let n = input.len().min(PAD_LEN);
    buf[..n].copy_from_slice(&input[..n]);
    buf[PAD_LEN..].copy_from_slice(&(input.len() as u64).to_le_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, password: &str, role: Role) -> ApiUser {
        ApiUser {
            name: name.into(),
            hash: hex_sha256(password.as_bytes()),
            role,
        }
    }

    fn basic_header(user: &str, password: &str) -> String {
        let raw = format!("{user}:{password}");
        format!("Basic {}", STANDARD.encode(raw))
    }

    #[test]
    fn missing_header_returns_missing() {
        let users = vec![user("alice", "secret", Role::Admin)];
        assert!(matches!(check(None, &users), AuthOutcome::Missing));
    }

    #[test]
    fn wrong_scheme_returns_missing() {
        let users = vec![user("alice", "secret", Role::Admin)];
        let h = format!("Bearer {}", STANDARD.encode("alice:secret"));
        assert!(matches!(check(Some(&h), &users), AuthOutcome::Missing));
    }

    #[test]
    fn malformed_base64_returns_missing() {
        let users = vec![user("alice", "secret", Role::Admin)];
        assert!(matches!(
            check(Some("Basic !!!not base64!!!"), &users),
            AuthOutcome::Missing
        ));
    }

    #[test]
    fn missing_colon_returns_missing() {
        let users = vec![user("alice", "secret", Role::Admin)];
        let h = format!("Basic {}", STANDARD.encode("nocolon"));
        assert!(matches!(check(Some(&h), &users), AuthOutcome::Missing));
    }

    #[test]
    fn correct_credential_authenticates_with_role() {
        let users = vec![
            user("alice", "secret", Role::Admin),
            user("bob", "hunter2", Role::ReadOnly),
        ];
        let h = basic_header("bob", "hunter2");
        match check(Some(&h), &users) {
            AuthOutcome::Authenticated(id) => {
                assert_eq!(id.name, "bob");
                assert_eq!(id.role, Role::ReadOnly);
            }
            _ => panic!("expected Authenticated"),
        }
    }

    #[test]
    fn wrong_password_returns_invalid() {
        let users = vec![user("alice", "secret", Role::Admin)];
        let h = basic_header("alice", "wrong");
        assert!(matches!(check(Some(&h), &users), AuthOutcome::Invalid));
    }

    #[test]
    fn unknown_user_returns_invalid() {
        let users = vec![user("alice", "secret", Role::Admin)];
        let h = basic_header("mallory", "secret");
        assert!(matches!(check(Some(&h), &users), AuthOutcome::Invalid));
    }

    #[test]
    fn empty_user_list_rejects_everything() {
        let h = basic_header("alice", "secret");
        assert!(matches!(check(Some(&h), &[]), AuthOutcome::Invalid));
    }

    #[test]
    fn case_insensitive_basic_scheme() {
        let users = vec![user("alice", "secret", Role::Admin)];
        let raw = format!("alice:{}", "secret");
        let h = format!("basic {}", STANDARD.encode(raw));
        assert!(matches!(
            check(Some(&h), &users),
            AuthOutcome::Authenticated(_)
        ));
    }

    #[test]
    fn oversized_payload_returns_missing() {
        let big = "a".repeat(MAX_DECODED_CREDENTIAL_BYTES + 1);
        let h = format!("Basic {}", STANDARD.encode(big));
        let users = vec![user("alice", "secret", Role::Admin)];
        assert!(matches!(check(Some(&h), &users), AuthOutcome::Missing));
    }
}
