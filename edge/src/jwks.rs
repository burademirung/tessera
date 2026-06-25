//! JWKS document assembly (RFC 7517). Pure + host-tested. The two keys are the
//! EdDSA internal key and the RS256 cloud key — distinct kid, use:"sig".

use serde_json::{json, Value};
use std::collections::HashSet;

/// Forbidden private-key JWK members — must never appear in a published JWKS.
const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "k"];

/// Assemble the RFC 7517 JWKS document from individual public JWKs.
pub fn assemble_jwks(keys: &[Value]) -> Value {
    json!({ "keys": keys })
}

/// Enforce publishing invariants: distinct kids, every key `use:"sig"`, no private members.
pub fn validate_jwks_invariants(jwks: &Value) -> Result<(), String> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("jwks.keys must be an array")?;
    let mut seen: HashSet<&str> = HashSet::new();
    for k in keys {
        let kid = k
            .get("kid")
            .and_then(Value::as_str)
            .ok_or("every key needs a kid")?;
        if !seen.insert(kid) {
            return Err(format!("duplicate kid: {kid}"));
        }
        if k.get("use").and_then(Value::as_str) != Some("sig") {
            return Err(format!("key {kid} must have use:\"sig\""));
        }
        for m in PRIVATE_MEMBERS {
            if k.get(*m).is_some() {
                return Err(format!("key {kid} leaks private member {m}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ed_jwk() -> serde_json::Value {
        json!({ "kty": "OKP", "crv": "Ed25519", "x": "abc", "use": "sig", "alg": "EdDSA", "kid": "int-2026-06" })
    }
    fn rsa_jwk() -> serde_json::Value {
        json!({ "kty": "RSA", "n": "xyz", "e": "AQAB", "use": "sig", "alg": "RS256", "kid": "cloud-2026-06" })
    }

    #[test]
    fn assembles_a_two_key_jwks_with_both_algorithms() {
        let jwks = assemble_jwks(&[ed_jwk(), rsa_jwk()]);
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
        let algs: Vec<&str> = keys.iter().map(|k| k["alg"].as_str().unwrap()).collect();
        assert!(algs.contains(&"EdDSA") && algs.contains(&"RS256"));
        validate_jwks_invariants(&jwks).unwrap();
    }

    #[test]
    fn rejects_duplicate_kids() {
        let mut a = ed_jwk();
        a["kid"] = json!("dup");
        let mut b = rsa_jwk();
        b["kid"] = json!("dup");
        let jwks = assemble_jwks(&[a, b]);
        assert!(validate_jwks_invariants(&jwks).is_err());
    }

    #[test]
    fn rejects_keys_without_use_sig() {
        let mut a = ed_jwk();
        a.as_object_mut().unwrap().remove("use");
        let jwks = assemble_jwks(&[a, rsa_jwk()]);
        assert!(validate_jwks_invariants(&jwks).is_err());
    }

    #[test]
    fn rejects_leaked_private_member() {
        let mut a = ed_jwk();
        a["d"] = json!("PRIVATE");
        let jwks = assemble_jwks(&[a, rsa_jwk()]);
        assert!(validate_jwks_invariants(&jwks).is_err());
    }
}
