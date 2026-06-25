//! RFC 7662 introspection. The endpoint MUST authenticate the caller; inactive
//! tokens reveal nothing but `{"active": false}`. Pure + host-tested.

use crate::jwt::VerifiedClaims;
use crate::session::SessionStatus;
use serde_json::{json, Value};

/// Constant-time-ish bearer check for the resource-server caller. The endpoint
/// MUST authenticate the caller (RFC 7662 §2.1).
pub fn caller_is_authenticated(auth_header: Option<&str>, expected_bearer: &str) -> bool {
    let presented = match auth_header.and_then(|h| h.strip_prefix("Bearer ")) {
        Some(t) => t,
        None => return false,
    };
    let a = presented.as_bytes();
    let b = expected_bearer.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Build an introspection response for an opaque session. Inactive tokens reveal
/// nothing but `{"active": false}`.
pub fn introspection_response_from_session(
    status: SessionStatus,
    sub: Option<&str>,
    exp: Option<u64>,
) -> Value {
    if status != SessionStatus::Active {
        return json!({ "active": false });
    }
    let mut out = json!({ "active": true });
    let obj = out.as_object_mut().unwrap();
    if let Some(s) = sub {
        obj.insert("sub".into(), json!(s));
    }
    if let Some(e) = exp {
        obj.insert("exp".into(), json!(e));
    }
    out
}

/// Build an introspection response for a (locally verified) JWT access token.
pub fn introspection_response_from_jwt(claims: &VerifiedClaims, now: u64) -> Value {
    if now >= claims.exp {
        return json!({ "active": false });
    }
    json!({
        "active": true,
        "sub": claims.sub,
        "iss": claims.iss,
        "aud": claims.aud,
        "exp": claims.exp,
        "token_type": "at+jwt",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionStatus;

    #[test]
    fn unauthenticated_caller_is_rejected() {
        assert!(!caller_is_authenticated(None, "s3cret-rs-token"));
        assert!(!caller_is_authenticated(
            Some("Bearer wrong"),
            "s3cret-rs-token"
        ));
        assert!(caller_is_authenticated(
            Some("Bearer s3cret-rs-token"),
            "s3cret-rs-token"
        ));
    }

    #[test]
    fn active_session_introspection_includes_sub_and_exp() {
        let r = introspection_response_from_session(
            SessionStatus::Active,
            Some("u-1"),
            Some(1_750_000_600),
        );
        assert_eq!(r["active"], true);
        assert_eq!(r["sub"], "u-1");
        assert_eq!(r["exp"], 1_750_000_600u64);
    }

    #[test]
    fn inactive_session_reveals_only_active_false() {
        for s in [
            SessionStatus::Expired,
            SessionStatus::Revoked,
            SessionStatus::Unknown,
        ] {
            let r = introspection_response_from_session(s, Some("u-1"), Some(123));
            assert_eq!(r["active"], false);
            assert!(
                r.get("sub").is_none(),
                "must not leak sub for inactive token"
            );
            assert!(r.get("exp").is_none());
        }
    }
}
