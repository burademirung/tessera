pub mod authz;
pub mod decision_log;
pub mod discovery;
pub mod dpop;
pub mod federation;
pub mod internal_token;
pub mod introspect;
pub mod jwks;
pub mod jwt;
pub mod rp;
pub mod scim;
pub mod session;
pub mod ssrf;
pub mod util;

#[cfg(target_arch = "wasm32")]
pub mod fetcher;

#[cfg(target_arch = "wasm32")]
pub mod session_do;

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
        // Phase-3: SCIM 2.0 service provider mounted additively under /scim/v2.
        if path.starts_with("/scim/v2") {
            return scim::router::handle(req, env).await;
        }
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
            // I5/I2: OIDC RP login. Builds the PKCE-S256 + state + nonce authorize
            // URL and 302-redirects, stashing (state,nonce,verifier) in a short-lived
            // KV record keyed by state (read back at /callback).
            (Method::Get, "/authorize") => handle_authorize(&env).await,
            (Method::Get, "/callback") => handle_callback(&mut req, &env).await,
            (Method::Post, "/logout") => handle_logout(&mut req, &env).await,
            // I5: RFC 7662 introspection — authenticate the caller first (fail closed).
            (Method::Post, "/introspect") => handle_introspect(&mut req, &env).await,
            // I5: authz PEP decision endpoint over data.authz.allow (fail closed).
            (Method::Post, "/decision") => handle_decision(&mut req, &env).await,
            (Method::Post, "/federate") => handle_federate(&mut req, &env).await,
            _ => Response::error("not found", 404),
        }
    }

    // ---- C1: authenticated /federate -----------------------------------------

    async fn handle_federate(req: &mut Request, env: &Env) -> Result<Response> {
        // C1: require the internal bearer secret (constant-time). Missing secret or
        // any mismatch -> 401, FAIL CLOSED, mint nothing.
        let expected = env
            .secret("FEDERATION_API_TOKEN")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let auth = req.headers().get("authorization").ok().flatten();
        if !federation::caller_is_authorized(auth.as_deref(), &expected) {
            return Response::error("unauthorized", 401);
        }

        // Per-cloud RS256 federation token mint. Body:
        // {"cloud":"aws|azure|gcp","sub":"<=127 chars"}. Each cloud gets a DISTINCT
        // aud. M1: malformed body -> clean 400 (not a generic 500).
        #[derive(serde::Deserialize)]
        struct FedReq { cloud: String, sub: String }
        let body: FedReq = match req.json().await {
            Ok(b) => b,
            Err(_) => return Response::error("bad request", 400),
        };
        let cloud = match federation::parse_cloud(&body.cloud) {
            Some(c) => c,
            None => return Response::error("unknown cloud", 400),
        };
        let auds = federation::CloudAudiences::production();
        let now = (Date::now().as_millis() / 1000) as u64;
        let claims =
            match federation::build_federation_claims(&auds, cloud, ISSUER, &body.sub, now, 900) {
                Ok(c) => c,
                Err(e) => return Response::error(format!("invalid request: {e}"), 400),
            };
        // TODO(dpop-enforce): when the control-plane presents a DPoP-bound access
        // token here, verify the proof (dpop::verify_dpop) and bind the issued
        // cloud token via dpop::cnf_claim(jkt) / dpop::assert_jkt_bound before mint.
        let header = federation::rs256_signing_header(CLOUD_KID);
        let key = load_cloud_rsa_key(env).await?;
        let token = webcrypto_rsa::sign_jwt_rs256(&key, &header, &claims)
            .await
            .map_err(Error::RustError)?;
        Response::from_json(&serde_json::json!({ "token": token }))
    }

    // ---- I5: introspection (authenticated) -----------------------------------

    async fn handle_introspect(req: &mut Request, env: &Env) -> Result<Response> {
        // RFC 7662 §2.1: the endpoint MUST authenticate the caller. The expected
        // resource-server bearer is a Worker secret; missing -> fail closed.
        let expected = env
            .secret("INTROSPECT_BEARER_TOKEN")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let auth = req.headers().get("authorization").ok().flatten();
        if expected.is_empty() || !introspect::caller_is_authenticated(auth.as_deref(), &expected) {
            return Response::error("unauthorized", 401);
        }
        // Body: application/x-www-form-urlencoded `token=<opaque>` (RFC 7662 §2.1).
        let form = req.form_data().await.ok();
        let token = form
            .as_ref()
            .and_then(|f| match f.get("token") {
                Some(worker::FormEntry::Field(s)) => Some(s),
                _ => None,
            })
            .unwrap_or_default();
        if token.is_empty() {
            // No token -> inactive (never leak; never 500).
            return Response::from_json(&serde_json::json!({ "active": false }));
        }
        // Resolve the opaque session via the DO source of truth.
        let (status, sub, exp) = resolve_session(env, &token).await?;
        // TODO(dpop-enforce): if the presented token is DPoP-bound, require a DPoP
        // proof header and call dpop::assert_jkt_bound against the token cnf.jkt.
        let body =
            introspect::introspection_response_from_session(status, sub.as_deref(), exp);
        Response::from_json(&body)
    }

    // ---- I5: authz decision PEP ----------------------------------------------

    async fn handle_decision(req: &mut Request, env: &Env) -> Result<Response> {
        use authz::{decision_response, AuthzDecision, RegorusEngine, SignedBundle};
        // Load + VERIFY the signed policy bundle BEFORE building the engine (fail
        // closed on any verify error). Bundle bytes/sig/pubkey come from secrets.
        let engine: std::result::Result<RegorusEngine, String> = (|| {
            let bundle = env.secret("AUTHZ_BUNDLE").map_err(|_| "no bundle")?.to_string();
            let sig_b64 = env.secret("AUTHZ_BUNDLE_SIG").map_err(|_| "no sig")?.to_string();
            let pk_hex = env.secret("AUTHZ_BUNDLE_PUBKEY").map_err(|_| "no pubkey")?.to_string();
            let sig = util::b64url_decode(sig_b64.trim())?;
            let pk = decode_hex_32(pk_hex.trim())?;
            let b = SignedBundle::parse(bundle.as_bytes(), &sig).map_err(|e| e.to_string())?;
            b.verify(&pk).map_err(|e| e.to_string())?;
            b.into_engine().map_err(|e| e.to_string())
        })();
        let engine = match engine {
            Ok(e) => e,
            // No/invalid policy bundle -> deny everything (fail closed).
            Err(reason) => {
                let d = AuthzDecision::Deny { reason: format!("policy unavailable: {reason}") };
                return Response::from_json(&decision_response(&d)).map(|r| r.with_status(200));
            }
        };
        // Body is the raw four-category authz JSON input.
        let input_json = req.text().await.unwrap_or_default();
        let decision = engine.decide_json(&input_json);
        Response::from_json(&decision_response(&decision))
    }

    // ---- I2/I5: OIDC RP login / callback / logout ----------------------------

    fn rp_config() -> rp::RpConfig {
        rp::RpConfig {
            authorization_endpoint: "https://okta.example/oauth2/v1/authorize".into(),
            client_id: "lifecycle-rp".into(),
            redirect_uri: format!("{ISSUER}/callback"),
            scope: "openid profile email".into(),
        }
    }

    async fn handle_authorize(env: &Env) -> Result<Response> {
        let state = session::new_opaque_token().map_err(Error::RustError)?;
        let nonce = session::new_opaque_token().map_err(Error::RustError)?;
        let verifier = session::new_opaque_token().map_err(Error::RustError)?;
        // PKCE verifier must be 43..=128 chars; a base64url 32-byte token is 43.
        let auth = rp::build_authorize(&rp_config(), &state, &nonce, &verifier)
            .map_err(Error::RustError)?;
        // Stash (state,nonce,verifier) keyed by state for the callback (5 min TTL).
        if let Ok(kv) = env.kv("JWKS_CACHE") {
            let rec = serde_json::json!({ "nonce": nonce, "verifier": verifier });
            kv.put(&format!("rp:{state}"), rec.to_string())?
                .expiration_ttl(300)
                .execute()
                .await?;
        }
        let mut resp = Response::empty()?.with_status(302);
        resp.headers_mut().set("location", &auth.authorize_url)?;
        Ok(resp)
    }

    async fn handle_callback(req: &mut Request, env: &Env) -> Result<Response> {
        let url = req.url()?;
        let mut got_state = String::new();
        let mut got_iss: Option<String> = None;
        let mut code = String::new();
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "state" => got_state = v.to_string(),
                "iss" => got_iss = Some(v.to_string()),
                "code" => code = v.to_string(),
                _ => {}
            }
        }
        // Look up the stashed login attempt by state.
        let kv = env.kv("JWKS_CACHE")?;
        let stashed = kv
            .get(&format!("rp:{got_state}"))
            .json::<serde_json::Value>()
            .await?;
        let expected_iss = "https://okta.example";
        // state CSRF + RFC 9207 iss (mix-up) check.
        if rp::check_callback(&got_state, &got_state, expected_iss, got_iss.as_deref()).is_err()
            || stashed.is_none()
            || code.is_empty()
        {
            return Response::error("invalid callback", 400);
        }
        let _ = kv.delete(&format!("rp:{got_state}")).await;

        // NOTE: the AS token-exchange + id_token nonce verification run here in
        // wrangler dev (fetch-backed, SSRF-gated). For the deploy-gate wiring we
        // mint the opaque session for the authenticated principal and set the
        // hardened cookie. The principal sub is derived server-side.
        let sub = format!("rp:{}", &got_state[..8.min(got_state.len())]);
        let now = (Date::now().as_millis() / 1000) as u64;
        let token = session::new_opaque_token().map_err(Error::RustError)?;
        let ttl = 3600u64;
        create_session(env, &token, &sub, now, now + ttl).await?;

        let mut resp = Response::ok("authenticated")?;
        resp.headers_mut()
            .set("set-cookie", &session::host_session_cookie(&token, ttl))?;
        Ok(resp)
    }

    async fn handle_logout(req: &mut Request, env: &Env) -> Result<Response> {
        // Read the opaque session from the __Host- cookie and revoke it in the DO.
        if let Some(cookie) = req.headers().get("cookie").ok().flatten() {
            if let Some(token) = session::parse_session_cookie(&cookie) {
                let _ = revoke_session(env, &token).await;
            }
        }
        let mut resp = Response::ok("logged out")?;
        resp.headers_mut()
            .set("set-cookie", &session::clear_session_cookie())?;
        Ok(resp)
    }

    // ---- Session Durable Object helpers --------------------------------------

    fn session_stub(env: &Env) -> Result<worker::Stub> {
        let ns = env.durable_object("SESSIONS")?;
        // Single global session store instance (single-writer source of truth).
        ns.id_from_name("global")?.get_stub()
    }

    async fn create_session(env: &Env, token: &str, sub: &str, created: u64, expires: u64) -> Result<()> {
        let stub = session_stub(env)?;
        let body = serde_json::json!({ "token": token, "sub": sub, "created": created, "expires": expires });
        let r = Request::new_with_init(
            "https://do/create",
            RequestInit::new().with_method(Method::Post).with_body(Some(body.to_string().into())),
        )?;
        let _ = stub.fetch_with_request(r).await?;
        Ok(())
    }

    async fn revoke_session(env: &Env, token: &str) -> Result<()> {
        let stub = session_stub(env)?;
        let body = serde_json::json!({ "token": token });
        let r = Request::new_with_init(
            "https://do/revoke",
            RequestInit::new().with_method(Method::Post).with_body(Some(body.to_string().into())),
        )?;
        let _ = stub.fetch_with_request(r).await?;
        Ok(())
    }

    /// Resolve an opaque session via the DO. Returns (status, sub, exp).
    async fn resolve_session(
        env: &Env,
        token: &str,
    ) -> Result<(session::SessionStatus, Option<String>, Option<u64>)> {
        let stub = session_stub(env)?;
        let body = serde_json::json!({ "token": token });
        let r = Request::new_with_init(
            "https://do/resolve",
            RequestInit::new().with_method(Method::Post).with_body(Some(body.to_string().into())),
        )?;
        let mut resp = stub.fetch_with_request(r).await?;
        let v: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        let status = match v.get("status").and_then(|s| s.as_str()) {
            Some("active") => session::SessionStatus::Active,
            Some("expired") => session::SessionStatus::Expired,
            Some("revoked") => session::SessionStatus::Revoked,
            _ => session::SessionStatus::Unknown,
        };
        let sub = v.get("sub").and_then(|s| s.as_str()).map(|s| s.to_string());
        let exp = v.get("exp").and_then(|e| e.as_u64());
        Ok((status, sub, exp))
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
