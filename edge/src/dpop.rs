//! DPoP (RFC 9449) proof verification: typ=dpop+jwt, embedded jwk, htm/htu/jti/iat,
//! optional ath; returns the RFC 7638 thumbprint (jkt) for cnf binding. Host-tested.

use crate::util::{b64url_decode, b64url_encode};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct DpopParams {
    pub htm: String,
    pub htu: String,
    pub max_iat_skew: u64,
    /// If Some, the proof MUST carry a matching `ath` (access-token hash binding).
    pub expected_ath: Option<String>,
}

/// RFC 7638 JWK thumbprint (SHA-256, base64url). For OKP: `{crv,kty,x}` only,
/// members in lexicographic order, no whitespace.
pub fn jwk_thumbprint_rfc7638(jwk: &Value) -> Result<String, String> {
    let kty = jwk.get("kty").and_then(Value::as_str).ok_or("jwk.kty")?;
    let canonical = match kty {
        "OKP" => {
            let crv = jwk.get("crv").and_then(Value::as_str).ok_or("jwk.crv")?;
            let x = jwk.get("x").and_then(Value::as_str).ok_or("jwk.x")?;
            format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
        }
        "RSA" => {
            let e = jwk.get("e").and_then(Value::as_str).ok_or("jwk.e")?;
            let n = jwk.get("n").and_then(Value::as_str).ok_or("jwk.n")?;
            format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
        }
        "EC" => {
            let crv = jwk.get("crv").and_then(Value::as_str).ok_or("jwk.crv")?;
            let x = jwk.get("x").and_then(Value::as_str).ok_or("jwk.x")?;
            let y = jwk.get("y").and_then(Value::as_str).ok_or("jwk.y")?;
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        other => return Err(format!("unsupported kty: {other}")),
    };
    Ok(b64url_encode(&Sha256::digest(canonical.as_bytes())))
}

/// Verify a DPoP proof. Returns the `jkt` (thumbprint of the embedded key) which
/// the caller binds via `cnf.jkt`. `seen_jti(jti)` returns true if the jti was
/// already used (replay).
pub fn verify_dpop(
    proof: &str,
    params: &DpopParams,
    now: u64,
    seen_jti: &mut dyn FnMut(&str) -> bool,
) -> Result<String, String> {
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err("malformed proof".to_string());
    }
    let header: Value =
        serde_json::from_slice(&b64url_decode(parts[0])?).map_err(|e| format!("header: {e}"))?;
    let claims: Value =
        serde_json::from_slice(&b64url_decode(parts[1])?).map_err(|e| format!("claims: {e}"))?;

    // 1. typ + alg
    if header.get("typ").and_then(Value::as_str) != Some("dpop+jwt") {
        return Err("typ must be dpop+jwt".to_string());
    }
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err("only EdDSA DPoP keys accepted".to_string());
    }

    // 2. embedded jwk -> verifying key + thumbprint
    let jwk = header.get("jwk").ok_or("missing embedded jwk")?;
    if jwk.get("crv").and_then(Value::as_str) != Some("Ed25519") {
        return Err("jwk must be Ed25519".to_string());
    }
    let x_bytes = b64url_decode(jwk.get("x").and_then(Value::as_str).ok_or("jwk.x")?)?;
    let x_arr: [u8; 32] = x_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "bad Ed25519 x length".to_string())?;
    let vk = VerifyingKey::from_bytes(&x_arr).map_err(|e| format!("bad key: {e}"))?;
    let jkt = jwk_thumbprint_rfc7638(jwk)?;

    // 3. signature
    let sig_bytes = b64url_decode(parts[2])?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "bad signature length".to_string())?;
    let sig = Signature::from_bytes(&sig_arr);
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    vk.verify_strict(signing_input.as_bytes(), &sig)
        .map_err(|e| format!("signature: {e}"))?;

    // 4. claims: htm, htu, iat, jti, optional ath
    if claims.get("htm").and_then(Value::as_str) != Some(params.htm.as_str()) {
        return Err("htm mismatch".to_string());
    }
    let htu = claims.get("htu").and_then(Value::as_str).ok_or("htu")?;
    if htu.trim_end_matches('/') != params.htu.trim_end_matches('/') {
        return Err("htu mismatch".to_string());
    }
    let iat = claims.get("iat").and_then(Value::as_u64).ok_or("iat")?;
    if now.abs_diff(iat) > params.max_iat_skew {
        return Err("iat outside acceptable window".to_string());
    }
    let jti = claims.get("jti").and_then(Value::as_str).ok_or("jti")?;
    if seen_jti(jti) {
        return Err("jti replay".to_string());
    }
    if let Some(expected) = &params.expected_ath {
        match claims.get("ath").and_then(Value::as_str) {
            Some(a) if a == expected => {}
            _ => return Err("ath mismatch or missing".to_string()),
        }
    }

    Ok(jkt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::b64url_encode;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const NOW: u64 = 1_750_000_000;

    fn make_proof(htm: &str, htu: &str, iat: u64, jti: &str, ath: Option<&str>) -> (String, String) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let x = b64url_encode(sk.verifying_key().as_bytes());
        let jwk = json!({ "kty": "OKP", "crv": "Ed25519", "x": x });
        let jkt = jwk_thumbprint_rfc7638(&jwk).unwrap();
        let header = json!({ "typ": "dpop+jwt", "alg": "EdDSA", "jwk": jwk });
        let mut claims = json!({ "htm": htm, "htu": htu, "iat": iat, "jti": jti });
        if let Some(a) = ath { claims["ath"] = json!(a); }
        let h = b64url_encode(serde_json::to_vec(&header).unwrap().as_slice());
        let p = b64url_encode(serde_json::to_vec(&claims).unwrap().as_slice());
        let signing_input = format!("{h}.{p}");
        let sig = sk.sign(signing_input.as_bytes());
        (format!("{signing_input}.{}", b64url_encode(&sig.to_bytes())), jkt)
    }

    fn params() -> DpopParams {
        DpopParams { htm: "POST".into(), htu: "https://idp.lifecycle.example/token".into(), max_iat_skew: 60, expected_ath: None }
    }

    #[test]
    fn accepts_a_valid_proof_and_returns_jkt() {
        let (proof, jkt) = make_proof("POST", "https://idp.lifecycle.example/token", NOW, "jti-1", None);
        let mut never = |_: &str| false;
        let got = verify_dpop(&proof, &params(), NOW, &mut never).unwrap();
        assert_eq!(got, jkt);
    }

    #[test]
    fn rejects_wrong_typ() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let x = b64url_encode(sk.verifying_key().as_bytes());
        let header = json!({ "typ": "jwt", "alg": "EdDSA", "jwk": { "kty":"OKP","crv":"Ed25519","x": x } });
        let claims = json!({ "htm":"POST","htu":"https://idp.lifecycle.example/token","iat":NOW,"jti":"j" });
        let h = b64url_encode(serde_json::to_vec(&header).unwrap().as_slice());
        let p = b64url_encode(serde_json::to_vec(&claims).unwrap().as_slice());
        use ed25519_dalek::Signer;
        let sig = sk.sign(format!("{h}.{p}").as_bytes());
        let proof = format!("{h}.{p}.{}", b64url_encode(&sig.to_bytes()));
        let mut never = |_: &str| false;
        assert!(verify_dpop(&proof, &params(), NOW, &mut never).is_err());
    }

    #[test]
    fn rejects_htm_or_htu_mismatch() {
        let (proof, _) = make_proof("GET", "https://idp.lifecycle.example/token", NOW, "j", None);
        let mut never = |_: &str| false;
        assert!(verify_dpop(&proof, &params(), NOW, &mut never).is_err());
        let (proof2, _) = make_proof("POST", "https://evil.example/token", NOW, "j", None);
        assert!(verify_dpop(&proof2, &params(), NOW, &mut never).is_err());
    }

    #[test]
    fn rejects_stale_iat() {
        let (proof, _) = make_proof("POST", "https://idp.lifecycle.example/token", NOW - 1000, "j", None);
        let mut never = |_: &str| false;
        assert!(verify_dpop(&proof, &params(), NOW, &mut never).is_err());
    }

    #[test]
    fn rejects_replayed_jti() {
        let (proof, _) = make_proof("POST", "https://idp.lifecycle.example/token", NOW, "dup", None);
        let mut always = |_: &str| true; // jti already seen
        assert!(verify_dpop(&proof, &params(), NOW, &mut always).is_err());
    }

    #[test]
    fn enforces_ath_when_expected() {
        let mut p = params();
        p.expected_ath = Some("expected-hash".into());
        let (proof_no_ath, _) = make_proof("POST", "https://idp.lifecycle.example/token", NOW, "j", None);
        let mut never = |_: &str| false;
        assert!(verify_dpop(&proof_no_ath, &p, NOW, &mut never).is_err());
        let (proof_ath, _) = make_proof("POST", "https://idp.lifecycle.example/token", NOW, "j2", Some("expected-hash"));
        assert!(verify_dpop(&proof_ath, &p, NOW, &mut never).is_ok());
    }

    #[test]
    fn thumbprint_matches_rfc7638_member_ordering() {
        // RFC 7638 §3.1: only crv, kty, x for OKP, lexicographic, no whitespace.
        let jwk = json!({ "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kty":"OKP","crv":"Ed25519" });
        let t = jwk_thumbprint_rfc7638(&jwk).unwrap();
        assert_eq!(t, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }
}
