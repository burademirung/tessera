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

/// The opaque session cookie name. The `__Host-` prefix is a browser-enforced
/// hardening contract: the cookie MUST be `Secure`, have `Path=/`, and carry NO
/// `Domain` attribute — otherwise the browser refuses to store it.
pub const SESSION_COOKIE_NAME: &str = "__Host-sid";

/// Build the `Set-Cookie` value for an issued opaque session (I2). Always sets
/// `__Host-` prefix + `HttpOnly; Secure; SameSite=Strict; Path=/` and never a
/// `Domain` (required for `__Host-`). `max_age_secs` bounds the cookie lifetime.
pub fn host_session_cookie(token: &str, max_age_secs: u64) -> String {
    format!(
        "{name}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={age}",
        name = SESSION_COOKIE_NAME,
        age = max_age_secs,
    )
}

/// Build the `Set-Cookie` value that clears the session cookie on logout. Same
/// attributes (so the browser matches + replaces it) with `Max-Age=0`.
pub fn clear_session_cookie() -> String {
    format!(
        "{name}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        name = SESSION_COOKIE_NAME,
    )
}

/// Extract the opaque session token from a `Cookie` request header. Returns the
/// first `__Host-sid` value, or None. Pure + host-testable.
pub fn parse_session_cookie(cookie_header: &str) -> Option<String> {
    let needle = format!("{SESSION_COOKIE_NAME}=");
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&needle) {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
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
        SessionRecord {
            sub: "u-1".into(),
            created: NOW - 10,
            expires: NOW + 600,
            revoked: false,
        }
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

    #[test]
    fn host_session_cookie_has_all_hardening_attributes() {
        let c = host_session_cookie("opaque-token-abc", 3600);
        assert!(c.starts_with("__Host-sid=opaque-token-abc"));
        assert!(c.contains("HttpOnly"), "must be HttpOnly: {c}");
        assert!(c.contains("Secure"), "must be Secure: {c}");
        assert!(
            c.contains("SameSite=Strict"),
            "must be SameSite=Strict: {c}"
        );
        assert!(c.contains("Path=/"), "must set Path=/: {c}");
        // __Host- prefix forbids a Domain attribute.
        assert!(
            !c.to_lowercase().contains("domain="),
            "must NOT set Domain: {c}"
        );
        assert!(c.contains("Max-Age=3600"));
    }

    #[test]
    fn clear_session_cookie_expires_immediately() {
        let c = clear_session_cookie();
        assert!(c.starts_with("__Host-sid="));
        assert!(c.contains("Max-Age=0"));
        assert!(c.contains("HttpOnly") && c.contains("Secure") && c.contains("SameSite=Strict"));
    }

    #[test]
    fn parse_session_cookie_extracts_host_sid() {
        assert_eq!(
            parse_session_cookie("foo=1; __Host-sid=tok-xyz; bar=2").as_deref(),
            Some("tok-xyz")
        );
        assert_eq!(
            parse_session_cookie("__Host-sid=only").as_deref(),
            Some("only")
        );
        assert_eq!(parse_session_cookie("other=1"), None);
        assert_eq!(parse_session_cookie("__Host-sid="), None);
    }
}
