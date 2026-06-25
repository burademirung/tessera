//! OIDC RP: PKCE S256, state, nonce, RFC 9207 issuer check. Pure + host-tested.
//! (The token-exchange HTTP call is `fetch`-backed and exercised in wrangler dev.)

use crate::util::b64url_encode;
use sha2::{Digest, Sha256};

pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

#[derive(Clone, Debug)]
pub struct RpConfig {
    pub authorization_endpoint: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
}

pub struct AuthRequest {
    pub authorize_url: String,
    pub state: String,
    pub nonce: String,
    pub verifier: String,
}

/// Derive the S256 PKCE challenge from a verifier (RFC 7636 §4.2).
pub fn pkce_from_verifier(verifier: &str) -> Result<PkcePair, String> {
    if verifier.len() < 43 || verifier.len() > 128 {
        return Err(format!(
            "verifier length {} out of 43..=128",
            verifier.len()
        ));
    }
    let digest = Sha256::digest(verifier.as_bytes());
    Ok(PkcePair {
        verifier: verifier.to_string(),
        challenge: b64url_encode(&digest),
    })
}

fn pct(s: &str) -> String {
    // Minimal RFC 3986 query-component encoding for the values we emit.
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build the authorize URL. ALWAYS sends `code_challenge_method=S256` explicitly
/// (omitting it defaults to `plain` — the top RP bug).
pub fn build_authorize(
    cfg: &RpConfig,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> Result<AuthRequest, String> {
    let pkce = pkce_from_verifier(verifier)?;
    let url = format!(
        "{base}?response_type=code&client_id={cid}&redirect_uri={ru}&scope={sc}\
         &state={st}&nonce={nc}&code_challenge={cc}&code_challenge_method=S256",
        base = cfg.authorization_endpoint,
        cid = pct(&cfg.client_id),
        ru = pct(&cfg.redirect_uri),
        sc = pct(&cfg.scope),
        st = pct(state),
        nc = pct(nonce),
        cc = pct(&pkce.challenge),
    );
    Ok(AuthRequest {
        authorize_url: url,
        state: state.to_string(),
        nonce: nonce.to_string(),
        verifier: verifier.to_string(),
    })
}

/// Validate the callback: state must match (CSRF) and, per RFC 9207, the returned
/// `iss` must equal the AS we directed the user to (mix-up defense for Okta+Entra).
pub fn check_callback(
    expected_state: &str,
    got_state: &str,
    expected_iss: &str,
    got_iss: Option<&str>,
) -> Result<(), String> {
    if expected_state != got_state {
        return Err("state mismatch (possible CSRF)".to_string());
    }
    match got_iss {
        None => Err("missing RFC 9207 iss response parameter".to_string()),
        Some(iss) if iss.trim_end_matches('/') == expected_iss.trim_end_matches('/') => Ok(()),
        Some(iss) => Err(format!("iss mismatch (mix-up): {iss} != {expected_iss}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RpConfig {
        RpConfig {
            authorization_endpoint: "https://okta.example/oauth2/v1/authorize".into(),
            client_id: "lifecycle-rp".into(),
            redirect_uri: "https://idp.lifecycle.example/callback".into(),
            scope: "openid profile email".into(),
        }
    }

    #[test]
    fn pkce_uses_s256_and_is_deterministic_for_a_verifier() {
        // RFC 7636 Appendix B test vector.
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let p = pkce_from_verifier(v).unwrap();
        assert_eq!(p.challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert_eq!(p.verifier, v);
    }

    #[test]
    fn rejects_short_verifier() {
        assert!(pkce_from_verifier("tooshort").is_err());
    }

    #[test]
    fn authorize_url_sends_code_challenge_method_s256_explicitly() {
        let req = build_authorize(
            &cfg(),
            "st-abc",
            "nc-xyz",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        )
        .unwrap();
        assert!(req.authorize_url.contains("response_type=code"));
        assert!(req.authorize_url.contains("code_challenge_method=S256"));
        assert!(req.authorize_url.contains("state=st-abc"));
        assert!(req.authorize_url.contains("nonce=nc-xyz"));
        assert!(req.authorize_url.contains("client_id=lifecycle-rp"));
        assert!(!req.authorize_url.contains("code_challenge_method=plain"));
    }

    #[test]
    fn callback_requires_state_match() {
        assert!(check_callback(
            "st-abc",
            "st-abc",
            "https://okta.example",
            Some("https://okta.example")
        )
        .is_ok());
        assert!(check_callback(
            "st-abc",
            "WRONG",
            "https://okta.example",
            Some("https://okta.example")
        )
        .is_err());
    }

    #[test]
    fn callback_enforces_rfc9207_issuer() {
        assert!(check_callback(
            "s",
            "s",
            "https://okta.example",
            Some("https://entra.example")
        )
        .is_err());
        assert!(check_callback("s", "s", "https://okta.example", None).is_err());
    }
}
