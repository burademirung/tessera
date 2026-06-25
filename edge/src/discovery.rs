//! OIDC discovery document. Pure + host-tested.

use serde_json::{json, Value};

#[derive(Clone, Debug)]
pub struct IssuerConfig {
    pub issuer: String,
}

/// OIDC discovery document. The `issuer` is byte-identical with the value the
/// clouds are configured to trust; all endpoints derive from it.
pub fn openid_configuration(cfg: &IssuerConfig) -> Value {
    let i = cfg.issuer.trim_end_matches('/');
    json!({
        "issuer": i,
        "jwks_uri": format!("{i}/jwks"),
        "authorization_endpoint": format!("{i}/authorize"),
        "token_endpoint": format!("{i}/token"),
        "introspection_endpoint": format!("{i}/introspect"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA", "RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid", "profile", "email"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "nbf"]
    })
}

/// A consumer-side check (reused by the RP fetcher): the discovered `issuer`
/// MUST equal the issuer we anchored to (reject mismatched-issuer metadata).
pub fn validate_discovery(doc: &Value, expected_issuer: &str) -> Result<(), String> {
    let got = doc.get("issuer").and_then(Value::as_str).ok_or("no issuer")?;
    if got.trim_end_matches('/') != expected_issuer.trim_end_matches('/') {
        return Err(format!("issuer mismatch: {got} != {expected_issuer}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> IssuerConfig {
        IssuerConfig { issuer: "https://idp.lifecycle.example".into() }
    }

    #[test]
    fn issuer_is_byte_identical_and_endpoints_derive_from_it() {
        let doc = openid_configuration(&cfg());
        assert_eq!(doc["issuer"], "https://idp.lifecycle.example");
        assert_eq!(doc["jwks_uri"], "https://idp.lifecycle.example/jwks");
        assert_eq!(doc["authorization_endpoint"], "https://idp.lifecycle.example/authorize");
        assert_eq!(doc["token_endpoint"], "https://idp.lifecycle.example/token");
        assert_eq!(doc["introspection_endpoint"], "https://idp.lifecycle.example/introspect");
    }

    #[test]
    fn advertises_both_algs_code_flow_and_s256_only() {
        let doc = openid_configuration(&cfg());
        let algs: Vec<&str> = doc["id_token_signing_alg_values_supported"]
            .as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert!(algs.contains(&"EdDSA") && algs.contains(&"RS256"));
        assert_eq!(doc["response_types_supported"][0], "code");
        let pkce: Vec<&str> = doc["code_challenge_methods_supported"]
            .as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(pkce, vec!["S256"], "never advertise plain");
    }

    #[test]
    fn validate_discovery_enforces_issuer_match() {
        let doc = openid_configuration(&cfg());
        assert!(validate_discovery(&doc, "https://idp.lifecycle.example").is_ok());
        assert!(validate_discovery(&doc, "https://evil.example").is_err());
    }
}
