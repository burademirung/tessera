//! Opaque session tokens + record evaluation. Pure + host-tested. The strongly
//! consistent store is the Durable Object in `session_do.rs`.

use crate::util::b64url_encode;
use serde::{Deserialize, Serialize};

/// 256-bit CSPRNG opaque session token (base64url). Routed to crypto.getRandomValues
/// on Workers via the getrandom wasm_js backend.
pub fn new_opaque_token() -> Result<String, String> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| format!("getrandom: {e}"))?;
    Ok(b64url_encode(&buf))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionRecord {
    pub sub: String,
    pub created: u64,
    pub expires: u64,
    pub revoked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    Expired,
    Revoked,
    Unknown,
}

/// Decide a session's status. Revocation wins over expiry; missing = Unknown.
/// (KV is only a read-cache — the DO is the single source of truth.)
pub fn evaluate(record: Option<&SessionRecord>, now: u64) -> SessionStatus {
    match record {
        None => SessionStatus::Unknown,
        Some(r) if r.revoked => SessionStatus::Revoked,
        Some(r) if now >= r.expires => SessionStatus::Expired,
        Some(_) => SessionStatus::Active,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_750_000_000;

    fn rec() -> SessionRecord {
        SessionRecord { sub: "u-1".into(), created: NOW - 10, expires: NOW + 600, revoked: false }
    }

    #[test]
    fn opaque_token_has_at_least_128_bits_of_entropy() {
        let t = new_opaque_token().unwrap();
        assert!(t.len() >= 43, "token too short: {}", t.len());
        let t2 = new_opaque_token().unwrap();
        assert_ne!(t, t2, "tokens must be unique");
    }

    #[test]
    fn active_session_resolves_active() {
        assert!(matches!(evaluate(Some(&rec()), NOW), SessionStatus::Active));
    }

    #[test]
    fn expired_session_resolves_expired() {
        let mut r = rec();
        r.expires = NOW - 1;
        assert!(matches!(evaluate(Some(&r), NOW), SessionStatus::Expired));
    }

    #[test]
    fn revoked_session_resolves_revoked_even_if_unexpired() {
        let mut r = rec();
        r.revoked = true;
        assert!(matches!(evaluate(Some(&r), NOW), SessionStatus::Revoked));
    }

    #[test]
    fn unknown_session_resolves_unknown() {
        assert!(matches!(evaluate(None, NOW), SessionStatus::Unknown));
    }
}
