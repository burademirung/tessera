pub mod discovery;
pub mod federation;
pub mod internal_token;
pub mod jwks;
pub mod jwt;
pub mod rp;
pub mod util;

#[cfg(target_arch = "wasm32")]
pub mod webcrypto_rsa;

/// Pure hex decode for the 32-byte Ed25519 seed Secret. Host-testable.
pub fn decode_hex_32(s: &str) -> std::result::Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!("seed must be 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("hex: {e}"))?;
    }
    Ok(out)
}

#[cfg(target_arch = "wasm32")]
mod worker_entry {
    use super::*;
    use worker::*;

    const ISSUER: &str = "https://idp.lifecycle.example";
    const CLOUD_KID: &str = "cloud-2026-06";

    #[event(start)]
    fn start() {
        console_error_panic_hook::set_once();
    }

    #[event(fetch)]
    async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
        let path = req.path();
        match (req.method(), path.as_str()) {
            (Method::Get, "/.well-known/openid-configuration") => {
                let cfg = discovery::IssuerConfig { issuer: ISSUER.to_string() };
                let mut resp = Response::from_json(&discovery::openid_configuration(&cfg))?;
                resp.headers_mut()
                    .set("cache-control", "public, max-age=300")?;
                Ok(resp)
            }
            (Method::Get, "/jwks") => {
                let ed = load_internal_signer(&env)?.public_jwk();
                // RSA JWK is attached at runtime via the WebCrypto RSA key (Task 5),
                // cached in KV. For now publish the Ed key and any cached RSA JWK.
                let mut keys = vec![ed];
                if let Ok(kv) = env.kv("JWKS_CACHE") {
                    if let Some(rsa) = kv.get("rsa_jwk").json::<serde_json::Value>().await? {
                        keys.push(rsa);
                    }
                }
                let doc = jwks::assemble_jwks(&keys);
                jwks::validate_jwks_invariants(&doc)
                    .map_err(|e| Error::RustError(format!("jwks invariant: {e}")))?;
                let mut resp = Response::from_json(&doc)?;
                resp.headers_mut()
                    .set("cache-control", "public, max-age=300")?;
                Ok(resp)
            }
            (Method::Post, "/federate") => {
                // Per-cloud RS256 federation token mint. Body:
                // {"cloud":"aws|azure|gcp","sub":"<=127 chars"}. Each cloud gets a
                // DISTINCT aud — never reuse one token across clouds.
                #[derive(serde::Deserialize)]
                struct FedReq { cloud: String, sub: String }
                let body: FedReq = req.json().await?;
                let cloud = federation::parse_cloud(&body.cloud)
                    .ok_or_else(|| Error::RustError("unknown cloud".into()))?;
                let auds = federation::CloudAudiences::production();
                let now = (Date::now().as_millis() / 1000) as u64;
                let claims = federation::build_federation_claims(&auds, cloud, ISSUER, &body.sub, now, 900)
                    .map_err(Error::RustError)?;
                let header = federation::rs256_signing_header(CLOUD_KID);
                // Load the RSA PKCS8 (DER, base64-encoded) private key from a Secret
                // and sign via WebCrypto SubtleCrypto (Task 5).
                let key = load_cloud_rsa_key(&env).await?;
                let token = webcrypto_rsa::sign_jwt_rs256(&key, &header, &claims)
                    .await
                    .map_err(Error::RustError)?;
                Response::from_json(&serde_json::json!({ "token": token }))
            }
            _ => Response::error("not found", 404),
        }
    }

    /// Load the EdDSA internal signer from a 32-byte hex Secret (`INTERNAL_ED25519_SEED`).
    fn load_internal_signer(env: &Env) -> Result<internal_token::InternalSigner> {
        let hex = env.secret("INTERNAL_ED25519_SEED")?.to_string();
        let bytes = decode_hex_32(&hex).map_err(Error::RustError)?;
        internal_token::from_signing_key_bytes("int-2026-06", &bytes)
            .map_err(Error::RustError)
    }

    /// Import the cloud RS256 private key from the `CLOUD_RSA_PKCS8_DER_B64` Secret
    /// (PKCS8 DER, base64url-encoded) into a non-extractable WebCrypto signing key.
    async fn load_cloud_rsa_key(env: &Env) -> Result<web_sys::CryptoKey> {
        let b64 = env.secret("CLOUD_RSA_PKCS8_DER_B64")?.to_string();
        let der = util::b64url_decode(b64.trim()).map_err(Error::RustError)?;
        webcrypto_rsa::import_rsa_pkcs8(&der)
            .await
            .map_err(Error::RustError)
    }
}

#[cfg(test)]
mod lib_tests {
    use super::*;

    #[test]
    fn decode_hex_32_roundtrips_and_rejects_bad_length() {
        let hex = "00".repeat(32);
        let bytes = decode_hex_32(&hex).unwrap();
        assert_eq!(bytes, [0u8; 32]);
        assert!(decode_hex_32("00").is_err());
        assert!(decode_hex_32(&"zz".repeat(32)).is_err());
    }
}
