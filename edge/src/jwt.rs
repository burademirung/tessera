//! RFC 8725-compliant JWT verification: explicit alg allow-list, reject `none`,
//! one-key-one-alg, validate iss/aud/exp/nbf and (optionally) typ. Host-testable.

use crate::util::b64url_decode;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyAlg {
    EdDSA,
    RS256,
}

impl VerifyAlg {
    fn to_jwt(self) -> Algorithm {
        match self {
            VerifyAlg::EdDSA => Algorithm::EdDSA,
            VerifyAlg::RS256 => Algorithm::RS256,
        }
    }
    fn header_name(self) -> &'static str {
        match self {
            VerifyAlg::EdDSA => "EdDSA",
            VerifyAlg::RS256 => "RS256",
        }
    }
}

/// Read the raw JOSE header as JSON WITHOUT trusting it. We parse the header
/// ourselves (rather than `jsonwebtoken::decode_header`) so that a forged
/// `alg:"none"` — which is not a variant of `jsonwebtoken::Algorithm` and would
/// otherwise surface as an opaque `InvalidAlgorithmName` — is rejected with a
/// deterministic, controlled error message.
fn raw_header(token: &str) -> Result<Value, String> {
    let part = token.split('.').next().ok_or("malformed token")?;
    let bytes = b64url_decode(part)?;
    serde_json::from_slice(&bytes).map_err(|e| format!("bad header json: {e}"))
}

#[derive(Clone, Debug)]
pub struct VerifyParams {
    pub alg: VerifyAlg,
    pub issuer: String,
    pub audience: String,
    /// e.g. Some("at+jwt"); if Some, the header `typ` MUST match exactly.
    pub expected_typ: Option<String>,
    pub leeway_secs: u64,
}

#[derive(Clone, Debug)]
pub struct VerifiedClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub exp: u64,
    pub nbf: Option<u64>,
    pub extra: serde_json::Map<String, Value>,
}

/// Read the declared `alg` from the JWS header WITHOUT trusting it for verification.
pub fn parse_header_alg(token: &str) -> Result<String, String> {
    let header = raw_header(token)?;
    header
        .get("alg")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "missing alg in header".to_string())
}

/// Verify a JWT against exactly one expected algorithm (one-key-one-alg).
/// Rejects `alg:none`, algorithm confusion, and validates iss/aud/exp/nbf/typ.
pub fn verify_jwt(
    token: &str,
    key: &DecodingKey,
    params: &VerifyParams,
    now: u64,
) -> Result<VerifiedClaims, String> {
    // 1. Header gate: parse the RAW header ourselves and reject `alg:none` and
    //    anything other than the single expected alg BEFORE handing the token to
    //    the verifier (defeats RS256<->HS256 confusion and `none`).
    let header = raw_header(token)?;
    let declared = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or("missing alg in header")?;
    if declared.eq_ignore_ascii_case("none") {
        return Err("alg `none` is forbidden".to_string());
    }
    if declared != params.alg.header_name() {
        return Err(format!(
            "alg mismatch: declared {declared}, expected {}",
            params.alg.header_name()
        ));
    }

    // 2. typ check (RFC 8725 — require explicit token type at validation).
    if let Some(expected) = &params.expected_typ {
        match header.get("typ").and_then(Value::as_str) {
            Some(t) if t.eq_ignore_ascii_case(expected) => {}
            other => return Err(format!("typ mismatch: {other:?} != {expected}")),
        }
    }

    // 3. Strict validation, allow-list of exactly one alg.
    //    `jsonwebtoken` validates exp/nbf against the *system clock*; on WASM we
    //    cannot rely on it, so we disable its built-in time checks here and
    //    enforce our injected `now` against exp/nbf below.
    let mut v = Validation::new(params.alg.to_jwt());
    v.algorithms = vec![params.alg.to_jwt()];
    v.set_issuer(&[&params.issuer]);
    v.set_audience(&[&params.audience]);
    v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    v.leeway = params.leeway_secs;
    v.validate_exp = false;
    v.validate_nbf = false;

    let data = decode::<serde_json::Map<String, Value>>(token, key, &v)
        .map_err(|e| format!("verify failed: {e}"))?;
    let claims = data.claims;

    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or("missing exp")?;
    if now > exp + params.leeway_secs {
        return Err("token expired".to_string());
    }
    let nbf = claims.get("nbf").and_then(Value::as_u64);
    if let Some(nbf) = nbf {
        if now + params.leeway_secs < nbf {
            return Err("token not yet valid (nbf)".to_string());
        }
    }

    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or("missing sub")?
        .to_string();
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .ok_or("missing iss")?
        .to_string();
    let aud = match claims.get("aud") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => return Err("missing aud".to_string()),
    };

    Ok(VerifiedClaims {
        sub,
        iss,
        aud,
        exp,
        nbf,
        extra: claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{pkcs8::EncodePublicKey, SigningKey};
    use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
    use serde_json::json;

    const NOW: u64 = 1_750_000_000;

    fn ed_keys() -> (EncodingKey, DecodingKey) {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let priv_pem = sk.to_pkcs8_pem(Default::default()).unwrap();
        let pub_pem = sk
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        (
            EncodingKey::from_ed_pem(priv_pem.as_bytes()).unwrap(),
            DecodingKey::from_ed_pem(pub_pem.as_bytes()).unwrap(),
        )
    }

    fn sign(claims: serde_json::Value, typ: Option<&str>) -> String {
        let (enc, _) = ed_keys();
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = typ.map(|t| t.to_string());
        encode(&header, &claims, &enc).unwrap()
    }

    fn params() -> VerifyParams {
        VerifyParams {
            alg: VerifyAlg::EdDSA,
            issuer: "https://idp.lifecycle.example".into(),
            audience: "lifecycle-edge".into(),
            expected_typ: Some("at+jwt".into()),
            leeway_secs: 60,
        }
    }

    fn good_claims() -> serde_json::Value {
        json!({
            "sub": "user-1",
            "iss": "https://idp.lifecycle.example",
            "aud": "lifecycle-edge",
            "exp": NOW + 300,
            "nbf": NOW - 10,
            "iat": NOW - 10
        })
    }

    #[test]
    fn accepts_a_valid_token() {
        let (_, dk) = ed_keys();
        let token = sign(good_claims(), Some("at+jwt"));
        let c = verify_jwt(&token, &dk, &params(), NOW).unwrap();
        assert_eq!(c.sub, "user-1");
        assert_eq!(c.aud, vec!["lifecycle-edge".to_string()]);
    }

    #[test]
    fn rejects_alg_none() {
        use crate::util::b64url_encode;
        let header = b64url_encode(br#"{"alg":"none","typ":"at+jwt"}"#);
        let payload = b64url_encode(good_claims().to_string().as_bytes());
        let token = format!("{header}.{payload}.");
        let (_, dk) = ed_keys();
        let err = verify_jwt(&token, &dk, &params(), NOW).unwrap_err();
        assert!(err.contains("alg"), "got: {err}");
    }

    #[test]
    fn rejects_algorithm_confusion_rs256_when_eddsa_expected() {
        use crate::util::b64url_encode;
        let header = b64url_encode(br#"{"alg":"RS256","typ":"at+jwt"}"#);
        let payload = b64url_encode(good_claims().to_string().as_bytes());
        let token = format!("{header}.{payload}.AAAA");
        let (_, dk) = ed_keys();
        assert!(verify_jwt(&token, &dk, &params(), NOW).is_err());
    }

    #[test]
    fn rejects_wrong_issuer() {
        let (_, dk) = ed_keys();
        let mut c = good_claims();
        c["iss"] = json!("https://evil.example");
        let token = sign(c, Some("at+jwt"));
        assert!(verify_jwt(&token, &dk, &params(), NOW).is_err());
    }

    #[test]
    fn rejects_wrong_audience() {
        let (_, dk) = ed_keys();
        let mut c = good_claims();
        c["aud"] = json!("some-other-rs");
        let token = sign(c, Some("at+jwt"));
        assert!(verify_jwt(&token, &dk, &params(), NOW).is_err());
    }

    #[test]
    fn rejects_expired_token() {
        let (_, dk) = ed_keys();
        let mut c = good_claims();
        c["exp"] = json!(NOW - 1000);
        let token = sign(c, Some("at+jwt"));
        assert!(verify_jwt(&token, &dk, &params(), NOW).is_err());
    }

    #[test]
    fn rejects_not_yet_valid_token() {
        let (_, dk) = ed_keys();
        let mut c = good_claims();
        c["nbf"] = json!(NOW + 1000);
        let token = sign(c, Some("at+jwt"));
        assert!(verify_jwt(&token, &dk, &params(), NOW).is_err());
    }

    #[test]
    fn rejects_wrong_typ() {
        let (_, dk) = ed_keys();
        let token = sign(good_claims(), Some("JWT")); // expected at+jwt
        assert!(verify_jwt(&token, &dk, &params(), NOW).is_err());
    }

    #[test]
    fn parse_header_alg_reads_the_declared_alg() {
        let token = sign(good_claims(), Some("at+jwt"));
        assert_eq!(parse_header_alg(&token).unwrap(), "EdDSA");
    }
}
