//! EdDSA/Ed25519 signer for internal (session/RP-side) tokens. Host-testable.

use crate::util::b64url_encode;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{json, Value};

pub struct InternalSigner {
    kid: String,
    encoding: EncodingKey,
    pub verifying: VerifyingKey,
}

/// Build a signer from a 32-byte Ed25519 seed (loaded from a Cloudflare Secret).
pub fn from_signing_key_bytes(kid: &str, seed: &[u8; 32]) -> Result<InternalSigner, String> {
    let sk = SigningKey::from_bytes(seed);
    let priv_pem = sk
        .to_pkcs8_pem(Default::default())
        .map_err(|e| format!("pkcs8 encode: {e}"))?;
    let encoding =
        EncodingKey::from_ed_pem(priv_pem.as_bytes()).map_err(|e| format!("encoding key: {e}"))?;
    Ok(InternalSigner {
        kid: kid.to_string(),
        encoding,
        verifying: sk.verifying_key(),
    })
}

impl InternalSigner {
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Public JWK for the JWKS document. Never includes private material.
    pub fn public_jwk(&self) -> Value {
        let x = b64url_encode(self.verifying.as_bytes());
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "use": "sig",
            "alg": "EdDSA",
            "kid": self.kid,
        })
    }

    /// Sign an internal token. `typ` is set in the header (e.g. "at+jwt").
    pub fn sign_internal(
        &self,
        sub: &str,
        iss: &str,
        aud: &str,
        now: u64,
        ttl_secs: u64,
        typ: &str,
    ) -> Result<String, String> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        header.typ = Some(typ.to_string());
        let claims = json!({
            "sub": sub,
            "iss": iss,
            "aud": aud,
            "iat": now,
            "nbf": now,
            "exp": now + ttl_secs,
        });
        jsonwebtoken::encode(&header, &claims, &self.encoding).map_err(|e| format!("sign: {e}"))
    }

    /// Self-verify helper: the matching public PEM (used to build a DecodingKey).
    pub fn public_pem(&self) -> Result<String, String> {
        self.verifying
            .to_public_key_pem(Default::default())
            .map(|p| p.to_string())
            .map_err(|e| format!("public pem: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{verify_jwt, VerifyAlg, VerifyParams};
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use jsonwebtoken::DecodingKey;

    const NOW: u64 = 1_750_000_000;

    fn signer() -> InternalSigner {
        from_signing_key_bytes("int-2026-06", &[3u8; 32]).unwrap()
    }

    #[test]
    fn signed_internal_token_verifies_with_our_verifier() {
        let s = signer();
        let token = s
            .sign_internal(
                "user-9",
                "https://idp.lifecycle.example",
                "lifecycle-internal",
                NOW,
                600,
                "at+jwt",
            )
            .unwrap();
        let pub_pem = s.verifying.to_public_key_pem(Default::default()).unwrap();
        let dk = DecodingKey::from_ed_pem(pub_pem.as_bytes()).unwrap();
        let params = VerifyParams {
            alg: VerifyAlg::EdDSA,
            issuer: "https://idp.lifecycle.example".into(),
            audience: "lifecycle-internal".into(),
            expected_typ: Some("at+jwt".into()),
            leeway_secs: 60,
        };
        let c = verify_jwt(&token, &dk, &params, NOW).unwrap();
        assert_eq!(c.sub, "user-9");
    }

    #[test]
    fn public_jwk_is_a_sig_eddsa_okp_key() {
        let s = signer();
        let jwk = s.public_jwk();
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["alg"], "EdDSA");
        assert_eq!(jwk["kid"], "int-2026-06");
        assert!(!jwk["x"].as_str().unwrap().is_empty());
        assert!(
            jwk.get("d").is_none(),
            "private key must never be published"
        );
    }

    #[test]
    fn token_carries_kid_in_header() {
        let s = signer();
        let token = s
            .sign_internal(
                "u",
                "https://idp.lifecycle.example",
                "lifecycle-internal",
                NOW,
                600,
                "at+jwt",
            )
            .unwrap();
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.kid.as_deref(), Some("int-2026-06"));
    }
}
