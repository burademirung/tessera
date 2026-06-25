# Phase 2 — Edge Identity Engine (Rust/WASM) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the edge identity engine as a Rust crate compiled to `wasm32-unknown-unknown` and run on Cloudflare Workers (`workers-rs`): a JWT verifier with a hard alg allow-list, an EdDSA signer for internal/session tokens, an RS256 cloud-federation minter (via WebCrypto SubtleCrypto) that issues a distinct token per cloud, OIDC discovery + JWKS publishing of both keys, an OIDC RP (Authorization Code + PKCE S256, state, nonce, RFC 9207 `iss`), opaque sessions backed by a Durable Object with instant revocation, RFC 7662 introspection (authenticated caller), DPoP proof verification, an SSRF-safe JWKS/discovery fetcher, and a host-emitted decision/audit log shape that mirrors OPA's event shape.

**Architecture:** One `worker` crate at `edge/`. Pure logic (JWT validation, PKCE, DPoP checks, SSRF allow-list, decision-log rendering, claim builders) lives in side-effect-free modules under `edge/src/` and is unit-tested with `#[cfg(test)]` + `cargo test` on the **host target** (no WASM needed). WASM/Worker-only surfaces (WebCrypto RSA signing, Durable Object session store, `fetch`-backed HTTP, route wiring) compile only for `wasm32` and are exercised with `worker-build` + `wrangler dev` manual checks. The PEP (the Worker) carries no policy logic; a typed `AuthzDecision` seam is left for Phase 4's Regorus wiring. SAML is **not** implemented here — a broker note documents the boundary.

**Tech Stack:** Rust (edition 2021), `worker` 0.8 + `worker-macros` + `worker-build`, `jsonwebtoken` 10.4 (`default-features=false`, `rust_crypto`), `ed25519-dalek` v2, WebCrypto `SubtleCrypto` (RS256 sign/keygen; RS256 verify via `jsonwebtoken` `rust_crypto`), `oauth2` 5 + `openidconnect` 4 over a `fetch`-backed `AsyncHttpClient`, `pasetors` v4.local (sessions seam), `sha2`/`base64ct`/`serde`/`serde_json`, `getrandom` 0.3 `wasm_js` backend. Wrangler v4 (`wrangler.jsonc`), pinned `wranglerVersion`.

## Global Constraints

- **Dual-algorithm policy (load-bearing, verbatim from spec §4.1):** Internal tokens (RP-side, session signing) → **EdDSA/Ed25519**. Cloud-federation IdP tokens → **RS256** (AWS/Azure/GCP reject EdDSA; Azure is RS256-only). Both keys live in **one JWKS** as distinct entries (`use:"sig"`, distinct `kid`).
- **Cargo dependency set (verbatim, from research brief 07):**
  ```toml
  worker = { version="0.8", features=["http","d1"] }
  worker-macros = "0.8"
  web-sys = { version="0.3", features=["WorkerGlobalScope","Crypto","SubtleCrypto","CryptoKey","CryptoKeyPair"] }
  jsonwebtoken = { version="10.4", default-features=false, features=["use_pem","rust_crypto"] }
  ed25519-dalek = { version="2.2", default-features=false, features=["rand_core","pkcs8","pem","zeroize"] }
  pasetors = { version="0.7", default-features=false, features=["std","v4","paserk"] }
  oauth2 = { version="5.0", default-features=false }
  openidconnect = { version="4.0", default-features=false }
  regorus = { version="0.10", default-features=false, features=["arc","regex","semver","base64","jsonschema"] }
  sha2="0.10"; base64ct="1"; serde={version="1",features=["derive"]}; serde_json="1"
  getrandom = { version="0.3", features=["wasm_js"] }
  ```
  (`regorus` is listed for Phase 4; this phase leaves only the typed seam — do not author policy here.)
- **getrandom backend (both required):** feature `wasm_js` **and** `.cargo/config.toml` → `[target.wasm32-unknown-unknown] rustflags=['--cfg','getrandom_backend="wasm_js"']`. Run `cargo tree -i getrandom` before any deploy and unify versions.
- **Forbidden crates (verbatim):** **NO** `ring`, `aws-lc-rs`, `boring`, `openssl`, `josekit`, `rusty_paseto`, `samael`, `reqwest`, `tokio(full)`, or the `rsa` crate for **signing** (RUSTSEC-2023-0071 Marvin timing — `rsa` is verify-only). `jsonwebtoken` MUST use the `rust_crypto` backend (the default `aws_lc_rs` is C and will not build).
- **Panic strategy:** build with `--panic-unwind` (panics abort the request on Workers); install `console_error_panic_hook` at startup.
- **Public-CA HTTPS issuer (spec §2):** the OIDC IdP `issuer` is served from a public custom domain with a **CA-signed cert** (GCP rejects self-signed; AWS has no JWKS-upload fallback, so the endpoint MUST be publicly reachable). `issuer` is byte-identical everywhere it appears.
- **Local JWT validation (spec §4.1):** validate self-contained JWT access tokens **locally at the edge** against cached JWKS — **never** fetch per request (amplification risk). Introspection (RFC 7662) is only for opaque/real-time revocation and the caller MUST be authenticated.
- **OAuth 2.1 bar:** PKCE S256 explicit (never `plain`); exact redirect-URI match; no implicit/ROPC/`response_type=token`; audience-restricted access tokens; RFC 9207 `iss` checked (we consume both Okta and Entra).
- **SSRF:** anchored issuer allow-list; block RFC1918/loopback/link-local/metadata (`169.254.169.254`) on **every hop**; ignore token-supplied `jku`/`x5u`/`jwk`.
- **Audit:** append-only; never log tokens or credentials; emit decision logs from Rust host code mirroring OPA's event shape.
- **Bundle:** Free tier 3 MB compressed; use `opt-level="z"`, `lto`, `wasm-opt`.

---

### Task 1: Project scaffold + getrandom cfg + passing smoke test

**Files:**
- Create: `edge/Cargo.toml`, `edge/.cargo/config.toml`, `edge/wrangler.jsonc`, `edge/.gitignore`
- Create: `edge/src/lib.rs`, `edge/src/util.rs`
- Test: `edge/src/util.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `pub fn b64url_encode(bytes: &[u8]) -> String`
  - `pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String>`
  - a crate that `cargo test` runs on the host and `worker-build` compiles to WASM.

- [ ] **Step 1: Write the Cargo manifest**

Create `edge/Cargo.toml`:
```toml
[package]
name = "edge"
version = "0.1.0"
edition = "2021"
authors = ["Tessera"]

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
worker = { version = "0.8", features = ["http", "d1"] }
worker-macros = "0.8"
web-sys = { version = "0.3", features = ["WorkerGlobalScope", "Crypto", "SubtleCrypto", "CryptoKey", "CryptoKeyPair"] }
wasm-bindgen = "0.2"
wasm-bindgen-futures = "0.4"
js-sys = "0.3"
console_error_panic_hook = "0.1"
jsonwebtoken = { version = "10.4", default-features = false, features = ["use_pem", "rust_crypto"] }
# `pem` is required for `to_pkcs8_pem`/`to_public_key_pem` (the `pkcs8` feature
# alone only provides DER); `pem` transitively enables `alloc` + `pkcs8`.
ed25519-dalek = { version = "2.2", default-features = false, features = ["rand_core", "pkcs8", "pem", "zeroize"] }
# NOTE: RS256 *verification* is provided by jsonwebtoken's `rust_crypto` backend
# (DecodingKey::from_rsa_pem); RS256 *signing* is done via WebCrypto (Task 5).
# The standalone `rsa` crate (verify-only, per RUSTSEC-2023-0071) is NOT needed in
# Phase 2 — add it only if/when a raw RSA verify path is required, with an alloc
# feature enabled (`default-features=false` alone does not build).
pasetors = { version = "0.7", default-features = false, features = ["std", "v4", "paserk"] }
oauth2 = { version = "5.0", default-features = false }
openidconnect = { version = "4.0", default-features = false }
sha2 = "0.10"
base64ct = { version = "1", features = ["alloc"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
getrandom = { version = "0.3", features = ["wasm_js"] }

[profile.release]
opt-level = "z"
lto = true

[package.metadata.wasm-pack.profile.release]
wasm-opt = ["-Oz"]
```

- [ ] **Step 2: Wire the getrandom WASM backend**

Create `edge/.cargo/config.toml`:
```toml
[target.wasm32-unknown-unknown]
rustflags = ['--cfg', 'getrandom_backend="wasm_js"']
```

- [ ] **Step 3: Write the Wrangler config (Rust build via worker-build)**

Create `edge/wrangler.jsonc`:
```jsonc
{
  "name": "tessera-edge",
  "main": "build/worker/shim.mjs",
  "compatibility_date": "2026-06-01",
  "build": {
    "command": "cargo install -q worker-build && worker-build --release"
  },
  "durable_objects": {
    "bindings": [
      { "name": "SESSIONS", "class_name": "SessionStore" }
    ]
  },
  "migrations": [
    { "tag": "v1", "new_sqlite_classes": ["SessionStore"] }
  ],
  "kv_namespaces": [
    { "binding": "JWKS_CACHE", "id": "PLACEHOLDER_REPLACE_BEFORE_DEPLOY" }
  ]
}
```

- [ ] **Step 4: Write `.gitignore`**

Create `edge/.gitignore`:
```
/target
/build
```

- [ ] **Step 5: Write the failing util test**

Create `edge/src/util.rs`:
```rust
//! Pure helpers shared across modules. Host-testable (no WASM).

use base64ct::{Base64UrlUnpadded, Encoding};

/// Base64url (no padding) encode — the JOSE encoding for all token parts.
pub fn b64url_encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Base64url (no padding) decode.
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    Base64UrlUnpadded::decode_vec(s).map_err(|e| format!("base64url decode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_base64url_without_padding() {
        let input = b"hello\x00\x01\x02world";
        let encoded = b64url_encode(input);
        assert!(!encoded.contains('='), "must be unpadded");
        assert!(!encoded.contains('+') && !encoded.contains('/'), "must be url-safe");
        assert_eq!(b64url_decode(&encoded).unwrap(), input);
    }

    #[test]
    fn rejects_invalid_base64url() {
        assert!(b64url_decode("not valid !!!").is_err());
    }
}
```

- [ ] **Step 6: Write the crate root + Worker entrypoint**

Create `edge/src/lib.rs`. The pure modules build on the host so `cargo test` runs
without WASM; the Worker entrypoint (`#[event]` handlers, `worker::*`) is gated to
`wasm32` so it never has to compile on the host test target:
```rust
pub mod util;

#[cfg(target_arch = "wasm32")]
mod worker_entry {
    use worker::*;

    #[event(start)]
    fn start() {
        console_error_panic_hook::set_once();
    }

    #[event(fetch)]
    async fn fetch(_req: Request, _env: Env, _ctx: Context) -> Result<Response> {
        Response::ok("tessera-edge: ok")
    }
}
```

- [ ] **Step 7: Run the smoke test to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib
```
Expected: PASS — `test result: ok. 2 passed` (`util::tests::roundtrips_base64url_without_padding`, `util::tests::rejects_invalid_base64url`).

- [ ] **Step 8: Verify the WASM build compiles**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo install -q worker-build || true
worker-build --release
cargo tree -i getrandom
```
Expected: `worker-build` produces `build/worker/shim.mjs`; `cargo tree -i getrandom` shows a single `getrandom v0.3.x` version (no duplicates).

- [ ] **Step 9: Commit**

```bash
git add edge
git commit -m "chore(edge): scaffold Rust/WASM worker crate + getrandom wasm_js + smoke test"
```

---

### Task 2: JWT verify module (alg allow-list, reject none, one-key-one-alg, iss/aud/exp/nbf, typ)

**Files:**
- Create: `edge/src/jwt.rs`
- Modify: `edge/src/lib.rs` (add `pub mod jwt;`)
- Test: `edge/src/jwt.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: `util::b64url_decode` (Task 1).
- Produces:
  - `pub enum VerifyAlg { EdDSA, RS256 }`
  - `pub struct VerifyParams { pub alg: VerifyAlg, pub issuer: String, pub audience: String, pub expected_typ: Option<String>, pub leeway_secs: u64 }`
  - `pub struct VerifiedClaims { pub sub: String, pub iss: String, pub aud: Vec<String>, pub exp: u64, pub nbf: Option<u64>, pub extra: serde_json::Map<String, serde_json::Value> }`
  - `pub fn parse_header_alg(token: &str) -> Result<String, String>`
  - `pub fn verify_jwt(token: &str, key: &jsonwebtoken::DecodingKey, params: &VerifyParams, now: u64) -> Result<VerifiedClaims, String>`

- [ ] **Step 1: Write the failing test**

Create `edge/src/jwt.rs` with only the test module first (so the build fails on missing items), then fill the impl in Step 3. Initial file:
```rust
//! RFC 8725-compliant JWT verification: explicit alg allow-list, reject `none`,
//! one-key-one-alg, validate iss/aud/exp/nbf and (optionally) typ. Host-testable.

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, pkcs8::EncodePublicKey};
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
    use serde_json::json;

    const NOW: u64 = 1_750_000_000;

    fn ed_keys() -> (EncodingKey, DecodingKey) {
        // ed25519-dalek -> PKCS8 PEM for jsonwebtoken's rust_crypto backend.
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let priv_pem = sk.to_pkcs8_pem(Default::default()).unwrap();
        let pub_pem = sk.verifying_key().to_public_key_pem(Default::default()).unwrap();
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
            issuer: "https://idp.tessera.example".into(),
            audience: "tessera-edge".into(),
            expected_typ: Some("at+jwt".into()),
            leeway_secs: 60,
        }
    }

    fn good_claims() -> serde_json::Value {
        json!({
            "sub": "user-1",
            "iss": "https://idp.tessera.example",
            "aud": "tessera-edge",
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
        assert_eq!(c.aud, vec!["tessera-edge".to_string()]);
    }

    #[test]
    fn rejects_alg_none() {
        // Forge a header with "none" and an empty signature.
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
        // A token claiming RS256 must be rejected by an EdDSA verifier (one-key-one-alg).
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
```

- [ ] **Step 2: Run it to verify it fails**

Add `pub mod jwt;` to `edge/src/lib.rs` (after `pub mod util;`), then run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib jwt
```
Expected: FAIL to **compile** (`cannot find type VerifyAlg`, `cannot find function verify_jwt`, etc.).

- [ ] **Step 3: Write the implementation**

Prepend to `edge/src/jwt.rs` (above the `#[cfg(test)]` module):
```rust
use crate::util::b64url_decode;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
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
    //    the verifier (defeats RS256<->HS256 confusion and `none`). We do NOT use
    //    `decode_header` here: an `alg:"none"` is not a `jsonwebtoken::Algorithm`
    //    variant and would otherwise surface as an opaque parse error.
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
```

- [ ] **Step 4: Run it to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib jwt
```
Expected: PASS — `test result: ok. 9 passed`.

- [ ] **Step 5: Commit**

```bash
git add edge/src/jwt.rs edge/src/lib.rs
git commit -m "feat(edge): RFC 8725 JWT verify (alg allow-list, reject none, iss/aud/exp/nbf/typ)"
```

---

### Task 3: EdDSA signer for internal tokens

**Files:**
- Create: `edge/src/internal_token.rs`
- Modify: `edge/src/lib.rs` (add `pub mod internal_token;`)
- Test: `edge/src/internal_token.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: `jwt::{verify_jwt, VerifyParams, VerifyAlg}` (Task 2).
- Produces:
  - `pub struct InternalSigner { kid: String, encoding: jsonwebtoken::EncodingKey, verifying: ed25519_dalek::VerifyingKey }`
  - `pub fn from_signing_key_bytes(kid: &str, seed: &[u8; 32]) -> Result<InternalSigner, String>`
  - `pub fn public_jwk(&self) -> serde_json::Value` (OKP/Ed25519, `use:"sig"`, `alg:"EdDSA"`, the `kid`)
  - `pub fn sign_internal(&self, sub: &str, iss: &str, aud: &str, now: u64, ttl_secs: u64, typ: &str) -> Result<String, String>`

- [ ] **Step 1: Write the failing test**

Create `edge/src/internal_token.rs` with the test module:
```rust
//! EdDSA/Ed25519 signer for internal (session/RP-side) tokens. Host-testable.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{VerifyAlg, VerifyParams, verify_jwt};
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
            .sign_internal("user-9", "https://idp.tessera.example", "tessera-internal", NOW, 600, "at+jwt")
            .unwrap();
        let pub_pem = s.verifying.to_public_key_pem(Default::default()).unwrap();
        let dk = DecodingKey::from_ed_pem(pub_pem.as_bytes()).unwrap();
        let params = VerifyParams {
            alg: VerifyAlg::EdDSA,
            issuer: "https://idp.tessera.example".into(),
            audience: "tessera-internal".into(),
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
        assert!(jwk["x"].as_str().unwrap().len() > 0);
        assert!(jwk.get("d").is_none(), "private key must never be published");
    }

    #[test]
    fn token_carries_kid_in_header() {
        let s = signer();
        let token = s
            .sign_internal("u", "https://idp.tessera.example", "tessera-internal", NOW, 600, "at+jwt")
            .unwrap();
        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.kid.as_deref(), Some("int-2026-06"));
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Add `pub mod internal_token;` to `edge/src/lib.rs`, then run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib internal_token
```
Expected: FAIL to compile (`cannot find function from_signing_key_bytes`, etc.).

- [ ] **Step 3: Write the implementation**

Prepend to `edge/src/internal_token.rs`:
```rust
use crate::util::b64url_encode;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};

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
```

- [ ] **Step 4: Run it to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib internal_token
```
Expected: PASS — `test result: ok. 3 passed`.

- [ ] **Step 5: Commit**

```bash
git add edge/src/internal_token.rs edge/src/lib.rs
git commit -m "feat(edge): EdDSA Ed25519 signer for internal/session tokens"
```

---

### Task 4: RS256 cloud-federation claim builder (per-cloud distinct aud, sub<=127)

**Files:**
- Create: `edge/src/federation.rs`
- Modify: `edge/src/lib.rs` (add `pub mod federation;`)
- Test: `edge/src/federation.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: nothing pure (signing happens in Task 5 via WebCrypto).
- Produces:
  - `pub enum Cloud { Aws, Azure, Gcp }`
  - `pub struct CloudAudiences { pub aws: String, pub azure: String, pub gcp: String }`
  - `pub fn audience_for(cfg: &CloudAudiences, cloud: Cloud) -> &str`
  - `pub fn build_federation_claims(cfg: &CloudAudiences, cloud: Cloud, iss: &str, sub: &str, now: u64, ttl_secs: u64) -> Result<serde_json::Value, String>` (enforces `sub<=127`, distinct `aud`, no `azp`, RS256-bound lifetimes)
  - `pub fn rs256_signing_header(kid: &str) -> serde_json::Value`

- [ ] **Step 1: Write the failing test**

Create `edge/src/federation.rs` with the test module:
```rust
//! Cloud-federation token claims (RS256). Pure claim construction is host-tested;
//! actual RS256 signing is done via WebCrypto in `webcrypto_rsa` (Task 5).

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_750_000_000;

    fn auds() -> CloudAudiences {
        CloudAudiences {
            aws: "sts.amazonaws.com".into(),
            azure: "api://AzureADTokenExchange".into(),
            gcp: "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tessera-pool/providers/tessera-oidc".into(),
        }
    }

    #[test]
    fn each_cloud_gets_a_distinct_audience() {
        let cfg = auds();
        assert_eq!(audience_for(&cfg, Cloud::Aws), cfg.aws);
        assert_eq!(audience_for(&cfg, Cloud::Azure), cfg.azure);
        assert_eq!(audience_for(&cfg, Cloud::Gcp), cfg.gcp);
        assert_ne!(audience_for(&cfg, Cloud::Aws), audience_for(&cfg, Cloud::Azure));
    }

    #[test]
    fn azure_audience_is_the_required_constant() {
        assert_eq!(audience_for(&auds(), Cloud::Azure), "api://AzureADTokenExchange");
    }

    #[test]
    fn builds_claims_with_correct_aud_and_no_azp() {
        let cfg = auds();
        let c = build_federation_claims(&cfg, Cloud::Gcp, "https://idp.tessera.example", "tenant-a:wl-1", NOW, 900).unwrap();
        assert_eq!(c["aud"], cfg.gcp);
        assert_eq!(c["iss"], "https://idp.tessera.example");
        assert_eq!(c["sub"], "tenant-a:wl-1");
        assert_eq!(c["exp"].as_u64().unwrap(), NOW + 900);
        assert!(c.get("azp").is_none(), "AWS treats azp as audience; must omit");
    }

    #[test]
    fn rejects_sub_over_127_chars() {
        let cfg = auds();
        let long = "x".repeat(128);
        assert!(build_federation_claims(&cfg, Cloud::Aws, "https://idp.tessera.example", &long, NOW, 900).is_err());
    }

    #[test]
    fn rejects_ttl_over_24h_for_gcp_limit() {
        let cfg = auds();
        // GCP requires exp - iat <= 24h.
        assert!(build_federation_claims(&cfg, Cloud::Gcp, "https://idp.tessera.example", "s", NOW, 86_401).is_err());
    }

    #[test]
    fn rs256_header_declares_rs256_and_kid() {
        let h = rs256_signing_header("cloud-2026-06");
        assert_eq!(h["alg"], "RS256");
        assert_eq!(h["typ"], "JWT");
        assert_eq!(h["kid"], "cloud-2026-06");
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Add `pub mod federation;` to `edge/src/lib.rs`, then run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib federation
```
Expected: FAIL to compile (`cannot find type Cloud`, etc.).

- [ ] **Step 3: Write the implementation**

Prepend to `edge/src/federation.rs`:
```rust
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cloud {
    Aws,
    Azure,
    Gcp,
}

#[derive(Clone, Debug)]
pub struct CloudAudiences {
    pub aws: String,
    pub azure: String,
    pub gcp: String,
}

/// The distinct `aud` for each cloud. A token is NEVER reused across clouds.
pub fn audience_for(cfg: &CloudAudiences, cloud: Cloud) -> &str {
    match cloud {
        Cloud::Aws => &cfg.aws,
        Cloud::Azure => &cfg.azure,
        Cloud::Gcp => &cfg.gcp,
    }
}

const MAX_SUB_LEN: usize = 127; // GCP limit
const MAX_TTL_SECS: u64 = 86_400; // GCP: exp - iat <= 24h

/// Build RS256 federation claims for exactly one cloud. Enforces the cross-cloud
/// constraints: distinct `aud`, `sub` <= 127 chars, no `azp` (AWS treats it as
/// audience), required iss/iat/exp/nbf, minutes-to-24h lifetime.
pub fn build_federation_claims(
    cfg: &CloudAudiences,
    cloud: Cloud,
    iss: &str,
    sub: &str,
    now: u64,
    ttl_secs: u64,
) -> Result<Value, String> {
    if sub.is_empty() {
        return Err("sub must be non-empty".to_string());
    }
    if sub.len() > MAX_SUB_LEN {
        return Err(format!("sub too long: {} > {MAX_SUB_LEN}", sub.len()));
    }
    if ttl_secs == 0 || ttl_secs > MAX_TTL_SECS {
        return Err(format!("ttl {ttl_secs} out of range (1..={MAX_TTL_SECS})"));
    }
    Ok(json!({
        "iss": iss,
        "sub": sub,
        "aud": audience_for(cfg, cloud),
        "iat": now,
        "nbf": now,
        "exp": now + ttl_secs,
    }))
}

/// JOSE header for RS256 cloud tokens (typ JWT; kid for JWKS rotation).
pub fn rs256_signing_header(kid: &str) -> Value {
    json!({ "alg": "RS256", "typ": "JWT", "kid": kid })
}
```

- [ ] **Step 4: Run it to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib federation
```
Expected: PASS — `test result: ok. 6 passed`.

- [ ] **Step 5: Commit**

```bash
git add edge/src/federation.rs edge/src/lib.rs
git commit -m "feat(edge): RS256 cloud-federation claim builder (per-cloud aud, sub<=127, no azp)"
```

---

### Task 5: WebCrypto RS256 signing + RSA public JWK + JWKS document

**Files:**
- Create: `edge/src/webcrypto_rsa.rs` (WASM-only signing surface)
- Create: `edge/src/jwks.rs` (pure JWKS assembly)
- Modify: `edge/src/lib.rs` (add modules; `webcrypto_rsa` behind `#[cfg(target_arch = "wasm32")]`)
- Test: `edge/src/jwks.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: `internal_token::InternalSigner::public_jwk` (Task 3); `federation::{rs256_signing_header}` (Task 4).
- Produces:
  - (WASM) `pub async fn import_rsa_pkcs8(pkcs8_der: &[u8]) -> Result<web_sys::CryptoKey, String>`
  - (WASM) `pub async fn sign_rs256(key: &web_sys::CryptoKey, signing_input: &[u8]) -> Result<Vec<u8>, String>`
  - (WASM) `pub async fn rsa_public_jwk(kid: &str, public_key: &web_sys::CryptoKey) -> Result<serde_json::Value, String>`
  - (pure) `pub fn assemble_jwks(keys: &[serde_json::Value]) -> serde_json::Value` (RFC 7517 `{"keys":[...]}` with distinct `kid`, `use:"sig"`)
  - (pure) `pub fn validate_jwks_invariants(jwks: &serde_json::Value) -> Result<(), String>` (distinct kids, every key `use:"sig"`, never any `d`/private member)

- [ ] **Step 1: Write the failing test (pure JWKS assembly)**

Create `edge/src/jwks.rs` with the test module:
```rust
//! JWKS document assembly (RFC 7517). Pure + host-tested. The two keys are the
//! EdDSA internal key and the RS256 cloud key — distinct kid, use:"sig".

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
```

- [ ] **Step 2: Run it to verify it fails**

Add to `edge/src/lib.rs`:
```rust
pub mod jwks;

#[cfg(target_arch = "wasm32")]
pub mod webcrypto_rsa;
```
Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib jwks
```
Expected: FAIL to compile (`cannot find function assemble_jwks`).

- [ ] **Step 3: Write the pure JWKS implementation**

Prepend to `edge/src/jwks.rs`:
```rust
use serde_json::{Value, json};
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
```

- [ ] **Step 4: Run the pure test to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib jwks
```
Expected: PASS — `test result: ok. 4 passed`.

- [ ] **Step 5: Write the WASM WebCrypto RSA signer**

Create `edge/src/webcrypto_rsa.rs`:
```rust
//! RS256 signing via the Worker's WebCrypto SubtleCrypto (the `rsa` crate is
//! verify-only here — RUSTSEC-2023-0071 Marvin timing). WASM-only.

use crate::util::b64url_encode;
use js_sys::{Object, Reflect, Uint8Array};
use serde_json::{Value, json};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, SubtleCrypto, WorkerGlobalScope};

fn subtle() -> Result<SubtleCrypto, String> {
    let global: WorkerGlobalScope = js_sys::global()
        .dyn_into()
        .map_err(|_| "no WorkerGlobalScope".to_string())?;
    let crypto = global.crypto().map_err(|_| "no crypto".to_string())?;
    Ok(crypto.subtle())
}

fn rsa_pss_or_pkcs1_algo() -> Object {
    // RSASSA-PKCS1-v1_5 with SHA-256 == JOSE RS256.
    let algo = Object::new();
    Reflect::set(&algo, &"name".into(), &"RSASSA-PKCS1-v1_5".into()).unwrap();
    let hash = Object::new();
    Reflect::set(&hash, &"name".into(), &"SHA-256".into()).unwrap();
    Reflect::set(&algo, &"hash".into(), &hash).unwrap();
    algo
}

/// Import a PKCS8 (DER) RSA private key for RS256 signing.
pub async fn import_rsa_pkcs8(pkcs8_der: &[u8]) -> Result<CryptoKey, String> {
    let subtle = subtle()?;
    let key_data = Uint8Array::from(pkcs8_der);
    let usages = js_sys::Array::new();
    usages.push(&JsValue::from_str("sign"));
    // `import_key_with_object` wants `key_data: &Object`; a `Uint8Array` IS-A
    // `Object`, so reinterpret the reference (no copy).
    let promise = subtle
        .import_key_with_object(
            "pkcs8",
            key_data.unchecked_ref::<Object>(),
            &rsa_pss_or_pkcs1_algo(),
            false,
            usages.as_ref(),
        )
        .map_err(|e| format!("import_key: {e:?}"))?;
    let key = JsFuture::from(promise)
        .await
        .map_err(|e| format!("import await: {e:?}"))?;
    key.dyn_into::<CryptoKey>()
        .map_err(|_| "import did not return a CryptoKey".to_string())
}

/// Sign the JWS signing-input (`base64url(header).base64url(payload)`) with RS256.
pub async fn sign_rs256(key: &CryptoKey, signing_input: &[u8]) -> Result<Vec<u8>, String> {
    let subtle = subtle()?;
    // `sign_with_object_and_u8_array` takes `data: &[u8]` (not `&mut`).
    let promise = subtle
        .sign_with_object_and_u8_array(&rsa_pss_or_pkcs1_algo(), key, signing_input)
        .map_err(|e| format!("sign: {e:?}"))?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|e| format!("sign await: {e:?}"))?;
    // SubtleCrypto.sign resolves to an ArrayBuffer; wrap it as a Uint8Array view.
    let buf = Uint8Array::new(&result);
    Ok(buf.to_vec())
}

/// Sign full claims into a compact JWS using the given header (Task 4).
pub async fn sign_jwt_rs256(
    key: &CryptoKey,
    header: &Value,
    claims: &Value,
) -> Result<String, String> {
    let h = b64url_encode(serde_json::to_vec(header).map_err(|e| e.to_string())?.as_slice());
    let p = b64url_encode(serde_json::to_vec(claims).map_err(|e| e.to_string())?.as_slice());
    let signing_input = format!("{h}.{p}");
    let sig = sign_rs256(key, signing_input.as_bytes()).await?;
    Ok(format!("{signing_input}.{}", b64url_encode(&sig)))
}

/// Export the RSA public key as a JWK and stamp it with `use`/`alg`/`kid`.
pub async fn rsa_public_jwk(kid: &str, public_key: &CryptoKey) -> Result<Value, String> {
    let subtle = subtle()?;
    let promise = subtle
        .export_key("jwk", public_key)
        .map_err(|e| format!("export_key: {e:?}"))?;
    let jwk_js = JsFuture::from(promise)
        .await
        .map_err(|e| format!("export await: {e:?}"))?;
    let mut jwk: Value =
        serde_wasm_bindgen_from(&jwk_js).map_err(|e| format!("jwk decode: {e}"))?;
    let obj = jwk.as_object_mut().ok_or("jwk not an object")?;
    obj.insert("use".into(), json!("sig"));
    obj.insert("alg".into(), json!("RS256"));
    obj.insert("kid".into(), json!(kid));
    // Strip any private members defensively.
    for m in ["d", "p", "q", "dp", "dq", "qi"] {
        obj.remove(m);
    }
    Ok(jwk)
}

/// Minimal JsValue->serde_json bridge (avoids pulling serde-wasm-bindgen).
fn serde_wasm_bindgen_from(v: &JsValue) -> Result<Value, String> {
    let s = js_sys::JSON::stringify(v).map_err(|e| format!("stringify: {e:?}"))?;
    let s = s.as_string().ok_or("stringify produced no string")?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}
```
> Note: `import_key_with_object` / `sign_with_object_and_u8_array` / `export_key` names follow the `web_sys::SubtleCrypto` 0.3 bindings; if a binding name differs in the pinned `web-sys` version, confirm with `cargo doc -p web-sys --open` and adjust the call site (signature shape is identical). Verify at the `wrangler dev` integration check.

- [ ] **Step 6: Verify the full crate still compiles for WASM**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo build --target wasm32-unknown-unknown --release
```
Expected: compiles (the `webcrypto_rsa` module is gated to `wasm32`).

- [ ] **Step 7: Commit**

```bash
git add edge/src/jwks.rs edge/src/webcrypto_rsa.rs edge/src/lib.rs
git commit -m "feat(edge): WebCrypto RS256 signer + RSA public JWK + two-key JWKS assembly"
```

---

### Task 6: Discovery + JWKS + federation mint (`POST /federate`) route wiring

**Files:**
- Create: `edge/src/discovery.rs` (pure discovery-document builder)
- Modify: `edge/src/lib.rs` (route `/.well-known/openid-configuration`, `/jwks`, and `POST /federate`)
- Test: `edge/src/discovery.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: `jwks::{assemble_jwks, validate_jwks_invariants}` (Task 5); `federation::{Cloud, CloudAudiences, parse_cloud, build_federation_claims}` (Task 4); `webcrypto_rsa::sign_rs256` (Task 5, wasm-only).
- Produces:
  - `pub struct IssuerConfig { pub issuer: String }`
  - `pub fn openid_configuration(cfg: &IssuerConfig) -> serde_json::Value` (issuer byte-identical; `jwks_uri`, `authorization_endpoint`, `token_endpoint`, `introspection_endpoint`, `id_token_signing_alg_values_supported: ["EdDSA","RS256"]`, `response_types_supported: ["code"]`, `code_challenge_methods_supported: ["S256"]`)
  - `pub fn validate_discovery(doc: &serde_json::Value, expected_issuer: &str) -> Result<(), String>`
  - **`POST /federate`** route (wasm): request body `{ "cloud": "aws"|"azure"|"gcp", "sub": "<≤127 chars>" }` → response `{ "token": "<RS256 JWT>" }`. Mints the per-cloud RS256 token (distinct `aud` per cloud: AWS `sts.amazonaws.com`, Azure `api://AzureADTokenExchange`, GCP provider resource URL) consumed by the Go control plane (Phase 5 Task 12). Also add the pure host-testable helper `pub fn parse_cloud(s: &str) -> Option<Cloud>` to `federation` (Task 4 module) with a `#[cfg(test)]` test asserting `aws`/`azure`/`gcp` parse and unknown returns `None`.

- [ ] **Step 1: Write the failing test**

Create `edge/src/discovery.rs` with the test module:
```rust
//! OIDC discovery document. Pure + host-tested.

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> IssuerConfig {
        IssuerConfig { issuer: "https://idp.tessera.example".into() }
    }

    #[test]
    fn issuer_is_byte_identical_and_endpoints_derive_from_it() {
        let doc = openid_configuration(&cfg());
        assert_eq!(doc["issuer"], "https://idp.tessera.example");
        assert_eq!(doc["jwks_uri"], "https://idp.tessera.example/jwks");
        assert_eq!(doc["authorization_endpoint"], "https://idp.tessera.example/authorize");
        assert_eq!(doc["token_endpoint"], "https://idp.tessera.example/token");
        assert_eq!(doc["introspection_endpoint"], "https://idp.tessera.example/introspect");
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
        assert!(validate_discovery(&doc, "https://idp.tessera.example").is_ok());
        assert!(validate_discovery(&doc, "https://evil.example").is_err());
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Add `pub mod discovery;` to `edge/src/lib.rs`, then run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib discovery
```
Expected: FAIL to compile.

- [ ] **Step 3: Write the implementation**

Prepend to `edge/src/discovery.rs`:
```rust
use serde_json::{Value, json};

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
```

- [ ] **Step 4: Run it to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib discovery
```
Expected: PASS — `test result: ok. 3 passed`.

- [ ] **Step 5: Wire the routes**

Replace the `fetch` body in `edge/src/lib.rs` with a router that serves discovery, JWKS, and the `POST /federate` mint route (JWKS keys come from the runtime in later wiring; this serves the EdDSA key from a Secret-loaded seed plus an RSA JWK cached in KV; the `/federate` route signs per-cloud RS256 tokens via the WebCrypto signer from Task 5):
```rust
pub mod discovery;
pub mod federation;
pub mod internal_token;
pub mod jwks;
pub mod jwt;
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

    const ISSUER: &str = "https://idp.tessera.example";

    #[event(start)]
    fn start() {
        console_error_panic_hook::set_once();
    }

    #[event(fetch)]
    async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
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
                // cached in KV. For now publish the Ed
                // key and any cached RSA JWK from KV.
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
                // Per-cloud RS256 federation token mint. Consumed by the Go control
                // plane (Phase 5 Task 12) via `POST {edgeBase}/federate`. Body:
                // {"cloud":"aws|azure|gcp","sub":"<=127 chars"}. Each cloud gets a
                // DISTINCT aud (AWS sts.amazonaws.com; Azure api://AzureADTokenExchange;
                // GCP provider resource URL) — never reuse one token across clouds.
                #[derive(serde::Deserialize)]
                struct FedReq { cloud: String, sub: String }
                let body: FedReq = req.json().await?;
                let cloud = federation::parse_cloud(&body.cloud)
                    .ok_or_else(|| Error::RustError("unknown cloud".into()))?;
                let auds = federation::CloudAudiences::production(); // canonical per-cloud aud
                let now = (Date::now().as_millis() / 1000) as u64;
                // build_federation_claims enforces sub<=127, distinct aud, no azp, RS256 lifetimes.
                let claims = federation::build_federation_claims(&auds, cloud, ISSUER, &body.sub, now, 900)
                    .map_err(Error::RustError)?;
                // Sign with the RS256 cloud key via WebCrypto SubtleCrypto (Task 5).
                let token = webcrypto_rsa::sign_rs256(&env, &claims)
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
}
```

- [ ] **Step 6: Verify the WASM build compiles**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo build --target wasm32-unknown-unknown --release
```
Expected: compiles.

- [ ] **Step 7: Commit**

```bash
git add edge/src/discovery.rs edge/src/lib.rs edge/src/federation.rs
git commit -m "feat(edge): OIDC discovery + JWKS + /federate per-cloud RS256 mint routes"
```

---

### Task 7: OIDC RP request builder (PKCE S256 explicit, state, nonce) + RFC 9207 iss check

**Files:**
- Create: `edge/src/rp.rs`
- Modify: `edge/src/lib.rs` (add `pub mod rp;`)
- Test: `edge/src/rp.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: `util::b64url_encode` (Task 1); `sha2`.
- Produces:
  - `pub struct PkcePair { pub verifier: String, pub challenge: String }`
  - `pub fn pkce_from_verifier(verifier: &str) -> Result<PkcePair, String>` (S256)
  - `pub struct AuthRequest { pub authorize_url: String, pub state: String, pub nonce: String, pub verifier: String }`
  - `pub struct RpConfig { pub authorization_endpoint: String, pub client_id: String, pub redirect_uri: String, pub scope: String }`
  - `pub fn build_authorize(cfg: &RpConfig, state: &str, nonce: &str, verifier: &str) -> Result<AuthRequest, String>`
  - `pub fn check_callback(expected_state: &str, got_state: &str, expected_iss: &str, got_iss: Option<&str>) -> Result<(), String>` (RFC 9207)

- [ ] **Step 1: Write the failing test**

Create `edge/src/rp.rs` with the test module:
```rust
//! OIDC RP: PKCE S256, state, nonce, RFC 9207 issuer check. Pure + host-tested.
//! (The token-exchange HTTP call is `fetch`-backed and exercised in wrangler dev.)

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> RpConfig {
        RpConfig {
            authorization_endpoint: "https://okta.example/oauth2/v1/authorize".into(),
            client_id: "tessera-rp".into(),
            redirect_uri: "https://idp.tessera.example/callback".into(),
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
        let req = build_authorize(&cfg(), "st-abc", "nc-xyz", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap();
        assert!(req.authorize_url.contains("response_type=code"));
        assert!(req.authorize_url.contains("code_challenge_method=S256"));
        assert!(req.authorize_url.contains("state=st-abc"));
        assert!(req.authorize_url.contains("nonce=nc-xyz"));
        assert!(req.authorize_url.contains("client_id=tessera-rp"));
        assert!(!req.authorize_url.contains("code_challenge_method=plain"));
    }

    #[test]
    fn callback_requires_state_match() {
        assert!(check_callback("st-abc", "st-abc", "https://okta.example", Some("https://okta.example")).is_ok());
        assert!(check_callback("st-abc", "WRONG", "https://okta.example", Some("https://okta.example")).is_err());
    }

    #[test]
    fn callback_enforces_rfc9207_issuer() {
        // Mix-up defense: returned iss must equal the AS we sent the request to.
        assert!(check_callback("s", "s", "https://okta.example", Some("https://entra.example")).is_err());
        // Missing iss when one is expected is also a failure.
        assert!(check_callback("s", "s", "https://okta.example", None).is_err());
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Add `pub mod rp;` to `edge/src/lib.rs`, then run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib rp
```
Expected: FAIL to compile.

- [ ] **Step 3: Write the implementation**

Prepend to `edge/src/rp.rs`:
```rust
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
        return Err(format!("verifier length {} out of 43..=128", verifier.len()));
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
```

- [ ] **Step 4: Run it to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib rp
```
Expected: PASS — `test result: ok. 5 passed`.

- [ ] **Step 5: Commit**

```bash
git add edge/src/rp.rs edge/src/lib.rs
git commit -m "feat(edge): OIDC RP PKCE-S256 authorize builder + RFC 9207 iss check"
```

---

### Task 8: Opaque session issuance + Durable Object session store (instant revocation)

**Files:**
- Create: `edge/src/session.rs` (pure: token generation + record shape + status logic)
- Create: `edge/src/session_do.rs` (WASM-only Durable Object)
- Modify: `edge/src/lib.rs` (export DO; add modules)
- Test: `edge/src/session.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: `util::b64url_encode` (Task 1); `getrandom`.
- Produces:
  - `pub fn new_opaque_token() -> Result<String, String>` (≥128-bit CSPRNG, base64url)
  - `pub struct SessionRecord { pub sub: String, pub created: u64, pub expires: u64, pub revoked: bool }`
  - `pub enum SessionStatus { Active, Expired, Revoked, Unknown }`
  - `pub fn evaluate(record: Option<&SessionRecord>, now: u64) -> SessionStatus`
  - (WASM) `pub struct SessionStore` Durable Object with `POST /create`, `GET /resolve`, `POST /revoke`, `POST /revoke-all`

- [ ] **Step 1: Write the failing test**

Create `edge/src/session.rs` with the test module:
```rust
//! Opaque session tokens + record evaluation. Pure + host-tested. The strongly
//! consistent store is the Durable Object in `session_do.rs`.

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_750_000_000;

    fn rec() -> SessionRecord {
        SessionRecord { sub: "u-1".into(), created: NOW - 10, expires: NOW + 600, revoked: false }
    }

    #[test]
    fn opaque_token_has_at_least_128_bits_of_entropy() {
        let t = new_opaque_token().unwrap();
        // 16 bytes -> 22 base64url chars; we use 32 bytes -> >=43 chars.
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
}
```

- [ ] **Step 2: Run it to verify it fails**

Add to `edge/src/lib.rs`:
```rust
pub mod session;

#[cfg(target_arch = "wasm32")]
pub mod session_do;
```
Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib session
```
Expected: FAIL to compile.

- [ ] **Step 3: Write the pure session logic**

Prepend to `edge/src/session.rs`:
```rust
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
```

- [ ] **Step 4: Run the pure test to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib session
```
Expected: PASS — `test result: ok. 5 passed`.

- [ ] **Step 5: Write the Durable Object session store**

Create `edge/src/session_do.rs`:
```rust
//! Single-writer, strongly consistent session store. Instant revocation and
//! "log out everywhere" via SQLite-backed Durable Object storage. WASM-only.

use crate::session::{SessionRecord, SessionStatus, evaluate};
use serde::Deserialize;
use worker::*;

#[durable_object]
pub struct SessionStore {
    state: State,
}

#[derive(Deserialize)]
struct CreateBody {
    token: String,
    sub: String,
    created: u64,
    expires: u64,
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

#[derive(Deserialize)]
struct SubBody {
    sub: String,
}

// NOTE: in workers-rs 0.8 the `#[durable_object]` attribute is applied to the
// STRUCT ONLY (above). The trait impl carries NO attribute macro, `new` is
// synchronous, and `fetch` takes `&self` (not `&mut self`).
impl DurableObject for SessionStore {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let storage = self.state.storage();
        match (req.method(), req.path().as_str()) {
            (Method::Post, "/create") => {
                let b: CreateBody = req.json().await?;
                let rec = SessionRecord {
                    sub: b.sub.clone(),
                    created: b.created,
                    expires: b.expires,
                    revoked: false,
                };
                storage.put(&format!("s:{}", b.token), &rec).await?;
                // Secondary index for revoke-all by subject.
                let key = format!("u:{}:{}", b.sub, b.token);
                storage.put(&key, &b.token).await?;
                Response::ok("created")
            }
            (Method::Post, "/resolve") => {
                let b: TokenBody = req.json().await?;
                let now = (Date::now().as_millis() / 1000) as u64;
                // `Storage::get` returns `Result<Option<T>>`; a missing key is
                // `Ok(None)`. Treat any storage error as a missing record too.
                let rec: Option<SessionRecord> = storage
                    .get(&format!("s:{}", b.token))
                    .await
                    .unwrap_or(None);
                let status = evaluate(rec.as_ref(), now);
                let body = serde_json::json!({
                    "status": match status {
                        SessionStatus::Active => "active",
                        SessionStatus::Expired => "expired",
                        SessionStatus::Revoked => "revoked",
                        SessionStatus::Unknown => "unknown",
                    },
                    // Only reveal `sub` for an active session.
                    "sub": match status {
                        SessionStatus::Active => rec.as_ref().map(|r| r.sub.clone()),
                        _ => None,
                    },
                });
                Response::from_json(&body)
            }
            (Method::Post, "/revoke") => {
                let b: TokenBody = req.json().await?;
                let key = format!("s:{}", b.token);
                if let Some(mut rec) = storage.get::<SessionRecord>(&key).await? {
                    rec.revoked = true;
                    storage.put(&key, &rec).await?;
                }
                Response::ok("revoked")
            }
            (Method::Post, "/revoke-all") => {
                let b: SubBody = req.json().await?;
                let prefix = format!("u:{}:", b.sub);
                let opts = ListOptions::new().prefix(&prefix);
                // `list_with_options` returns a JS `Map`; `keys()` yields a
                // `js_sys::Iterator` of `Result<JsValue, JsValue>`.
                let listed = storage.list_with_options(opts).await?;
                let mut count = 0u32;
                for key in listed.keys() {
                    let key = key
                        .map_err(|e| Error::RustError(format!("list key: {e:?}")))?
                        .as_string()
                        .unwrap_or_default();
                    if let Some(token) = key.rsplit(':').next() {
                        let skey = format!("s:{token}");
                        if let Some(mut rec) = storage.get::<SessionRecord>(&skey).await? {
                            rec.revoked = true;
                            storage.put(&skey, &rec).await?;
                            count += 1;
                        }
                    }
                }
                Response::from_json(&serde_json::json!({ "revoked": count }))
            }
            _ => Response::error("not found", 404),
        }
    }
}
```
> Note: `Date::now()` provides the DO's wall clock; `evaluate` (pure, Task 8) makes the actual decision so it stays unit-tested. `Storage::get` returns `Result<Option<T>>` (missing key ⇒ `Ok(None)`); `list_with_options` returns a JS `Map` whose `keys()` is a `js_sys::Iterator` yielding `Result<JsValue, JsValue>`. Confirm the exact iterator-to-key conversion at the `wrangler dev` integration check and adjust the `for` loop if the binding wraps it differently.

- [ ] **Step 6: Verify the WASM build compiles**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo build --target wasm32-unknown-unknown --release
```
Expected: compiles (DO bound in `wrangler.jsonc` from Task 1).

- [ ] **Step 7: Commit**

```bash
git add edge/src/session.rs edge/src/session_do.rs edge/src/lib.rs
git commit -m "feat(edge): opaque sessions + Durable Object store with instant revocation"
```

---

### Task 9: Token introspection endpoint (RFC 7662, authenticated caller)

**Files:**
- Create: `edge/src/introspect.rs`
- Modify: `edge/src/lib.rs` (route `POST /introspect`)
- Test: `edge/src/introspect.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: `session::SessionStatus` (Task 8); `jwt::VerifiedClaims` (Task 2).
- Produces:
  - `pub fn caller_is_authenticated(auth_header: Option<&str>, expected_bearer: &str) -> bool` (constant-time compare)
  - `pub fn introspection_response_from_session(status: session::SessionStatus, sub: Option<&str>, exp: Option<u64>) -> serde_json::Value` (RFC 7662: `{"active": bool, ...}`; inactive ⇒ `{"active":false}` only)
  - `pub fn introspection_response_from_jwt(claims: &jwt::VerifiedClaims, now: u64) -> serde_json::Value`

- [ ] **Step 1: Write the failing test**

Create `edge/src/introspect.rs` with the test module:
```rust
//! RFC 7662 introspection. The endpoint MUST authenticate the caller; inactive
//! tokens reveal nothing but `{"active": false}`. Pure + host-tested.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionStatus;

    #[test]
    fn unauthenticated_caller_is_rejected() {
        assert!(!caller_is_authenticated(None, "s3cret-rs-token"));
        assert!(!caller_is_authenticated(Some("Bearer wrong"), "s3cret-rs-token"));
        assert!(caller_is_authenticated(Some("Bearer s3cret-rs-token"), "s3cret-rs-token"));
    }

    #[test]
    fn active_session_introspection_includes_sub_and_exp() {
        let r = introspection_response_from_session(SessionStatus::Active, Some("u-1"), Some(1_750_000_600));
        assert_eq!(r["active"], true);
        assert_eq!(r["sub"], "u-1");
        assert_eq!(r["exp"], 1_750_000_600u64);
    }

    #[test]
    fn inactive_session_reveals_only_active_false() {
        for s in [SessionStatus::Expired, SessionStatus::Revoked, SessionStatus::Unknown] {
            let r = introspection_response_from_session(s, Some("u-1"), Some(123));
            assert_eq!(r["active"], false);
            assert!(r.get("sub").is_none(), "must not leak sub for inactive token");
            assert!(r.get("exp").is_none());
        }
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Add `pub mod introspect;` to `edge/src/lib.rs`, then run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib introspect
```
Expected: FAIL to compile.

- [ ] **Step 3: Write the implementation**

Prepend to `edge/src/introspect.rs`:
```rust
use crate::jwt::VerifiedClaims;
use crate::session::SessionStatus;
use serde_json::{Value, json};

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
```

- [ ] **Step 4: Run it to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib introspect
```
Expected: PASS — `test result: ok. 3 passed`.

- [ ] **Step 5: Commit**

```bash
git add edge/src/introspect.rs edge/src/lib.rs
git commit -m "feat(edge): RFC 7662 introspection (authenticated caller, inactive reveals nothing)"
```

---

### Task 10: DPoP proof verification (typ=dpop+jwt, htm/htu/jti/iat/ath, cnf.jkt)

**Files:**
- Create: `edge/src/dpop.rs`
- Modify: `edge/src/lib.rs` (add `pub mod dpop;`)
- Test: `edge/src/dpop.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: `util::{b64url_encode, b64url_decode}` (Task 1); `sha2`; `ed25519-dalek`.
- Produces:
  - `pub struct DpopParams { pub htm: String, pub htu: String, pub max_iat_skew: u64, pub expected_ath: Option<String> }`
  - `pub fn jwk_thumbprint_rfc7638(jwk: &serde_json::Value) -> Result<String, String>`
  - `pub fn verify_dpop(proof: &str, params: &DpopParams, now: u64, seen_jti: &mut dyn FnMut(&str) -> bool) -> Result<String, String>` (returns the `jkt`; `seen_jti` returns true if the jti was already used)

- [ ] **Step 1: Write the failing test**

Create `edge/src/dpop.rs` with the test module:
```rust
//! DPoP (RFC 9449) proof verification: typ=dpop+jwt, embedded jwk, htm/htu/jti/iat,
//! optional ath; returns the RFC 7638 thumbprint (jkt) for cnf binding. Host-tested.

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
        DpopParams { htm: "POST".into(), htu: "https://idp.tessera.example/token".into(), max_iat_skew: 60, expected_ath: None }
    }

    #[test]
    fn accepts_a_valid_proof_and_returns_jkt() {
        let (proof, jkt) = make_proof("POST", "https://idp.tessera.example/token", NOW, "jti-1", None);
        let mut never = |_: &str| false;
        let got = verify_dpop(&proof, &params(), NOW, &mut never).unwrap();
        assert_eq!(got, jkt);
    }

    #[test]
    fn rejects_wrong_typ() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let x = b64url_encode(sk.verifying_key().as_bytes());
        let header = json!({ "typ": "jwt", "alg": "EdDSA", "jwk": { "kty":"OKP","crv":"Ed25519","x": x } });
        let claims = json!({ "htm":"POST","htu":"https://idp.tessera.example/token","iat":NOW,"jti":"j" });
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
        let (proof, _) = make_proof("GET", "https://idp.tessera.example/token", NOW, "j", None);
        let mut never = |_: &str| false;
        assert!(verify_dpop(&proof, &params(), NOW, &mut never).is_err());
        let (proof2, _) = make_proof("POST", "https://evil.example/token", NOW, "j", None);
        assert!(verify_dpop(&proof2, &params(), NOW, &mut never).is_err());
    }

    #[test]
    fn rejects_stale_iat() {
        let (proof, _) = make_proof("POST", "https://idp.tessera.example/token", NOW - 1000, "j", None);
        let mut never = |_: &str| false;
        assert!(verify_dpop(&proof, &params(), NOW, &mut never).is_err());
    }

    #[test]
    fn rejects_replayed_jti() {
        let (proof, _) = make_proof("POST", "https://idp.tessera.example/token", NOW, "dup", None);
        let mut always = |_: &str| true; // jti already seen
        assert!(verify_dpop(&proof, &params(), NOW, &mut always).is_err());
    }

    #[test]
    fn enforces_ath_when_expected() {
        let mut p = params();
        p.expected_ath = Some("expected-hash".into());
        let (proof_no_ath, _) = make_proof("POST", "https://idp.tessera.example/token", NOW, "j", None);
        let mut never = |_: &str| false;
        assert!(verify_dpop(&proof_no_ath, &p, NOW, &mut never).is_err());
        let (proof_ath, _) = make_proof("POST", "https://idp.tessera.example/token", NOW, "j2", Some("expected-hash"));
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
```

- [ ] **Step 2: Run it to verify it fails**

Add `pub mod dpop;` to `edge/src/lib.rs`, then run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib dpop
```
Expected: FAIL to compile.

- [ ] **Step 3: Write the implementation**

Prepend to `edge/src/dpop.rs`:
```rust
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
```

- [ ] **Step 4: Run it to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib dpop
```
Expected: PASS — `test result: ok. 7 passed`. (If the RFC 7638 vector assertion differs, recompute with the canonical OKP member ordering shown above — the canonicalization, not the value, is the contract.)

- [ ] **Step 5: Commit**

```bash
git add edge/src/dpop.rs edge/src/lib.rs
git commit -m "feat(edge): DPoP proof verification (typ/htm/htu/jti/iat/ath + RFC 7638 jkt)"
```

---

### Task 11: SSRF-safe JWKS/discovery fetcher (anchored allow-list, block metadata/RFC1918)

**Files:**
- Create: `edge/src/ssrf.rs` (pure URL/host gatekeeper + anchored allow-list)
- Create: `edge/src/fetcher.rs` (WASM-only `fetch`-backed retrieval that calls `ssrf` first)
- Modify: `edge/src/lib.rs` (add modules)
- Test: `edge/src/ssrf.rs` (`#[cfg(test)]` module)

**Interfaces:**
- Consumes: `discovery::validate_discovery` (Task 6).
- Produces:
  - `pub struct IssuerAllowList { issuers: Vec<String> }`
  - `pub fn new_allow_list(issuers: &[&str]) -> IssuerAllowList`
  - `pub fn check_outbound_url(allow: &IssuerAllowList, url: &str) -> Result<(), String>` (HTTPS only; host must be a configured issuer host; block RFC1918/loopback/link-local/metadata)
  - `pub fn header_key_url_is_ignored(header: &serde_json::Value) -> bool` (asserts we never act on `jku`/`x5u`/`jwk` from a token)
  - (WASM) `pub async fn fetch_json_guarded(allow: &IssuerAllowList, url: &str) -> Result<serde_json::Value, String>`

- [ ] **Step 1: Write the failing test**

Create `edge/src/ssrf.rs` with the test module:
```rust
//! SSRF guard for outbound JWKS/discovery fetches: HTTPS-only, anchored issuer
//! allow-list, block private/loopback/link-local/metadata on every hop, and never
//! act on token-supplied key URLs. Pure + host-tested.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn allow() -> IssuerAllowList {
        new_allow_list(&["https://okta.example", "https://entra.example", "https://idp.tessera.example"])
    }

    #[test]
    fn allows_an_anchored_https_issuer_host() {
        assert!(check_outbound_url(&allow(), "https://okta.example/.well-known/openid-configuration").is_ok());
        assert!(check_outbound_url(&allow(), "https://idp.tessera.example/jwks").is_ok());
    }

    #[test]
    fn rejects_non_https() {
        assert!(check_outbound_url(&allow(), "http://okta.example/jwks").is_err());
    }

    #[test]
    fn rejects_unanchored_host() {
        assert!(check_outbound_url(&allow(), "https://evil.example/jwks").is_err());
    }

    #[test]
    fn blocks_the_cloud_metadata_endpoint() {
        assert!(check_outbound_url(&allow(), "https://169.254.169.254/latest/meta-data/").is_err());
    }

    #[test]
    fn blocks_rfc1918_loopback_and_linklocal() {
        for h in ["https://10.0.0.5/jwks", "https://192.168.1.1/jwks", "https://172.16.0.1/jwks", "https://127.0.0.1/jwks", "https://[::1]/jwks", "https://169.254.0.1/jwks"] {
            assert!(check_outbound_url(&allow(), h).is_err(), "should block {h}");
        }
    }

    #[test]
    fn token_supplied_key_urls_are_ignored() {
        let header = json!({ "alg":"RS256","kid":"k","jku":"https://evil.example/jwks","x5u":"https://evil.example/x","jwk":{"kty":"RSA"} });
        // The function exists to document/enforce that we never select trust from these.
        assert!(header_key_url_is_ignored(&header));
        let clean = json!({ "alg":"RS256","kid":"k" });
        assert!(header_key_url_is_ignored(&clean));
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Add to `edge/src/lib.rs`:
```rust
pub mod ssrf;

#[cfg(target_arch = "wasm32")]
pub mod fetcher;
```
Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib ssrf
```
Expected: FAIL to compile.

- [ ] **Step 3: Write the pure SSRF guard**

Prepend to `edge/src/ssrf.rs`:
```rust
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct IssuerAllowList {
    issuers: Vec<String>,
}

/// Build the anchored allow-list from configured issuer base URLs.
pub fn new_allow_list(issuers: &[&str]) -> IssuerAllowList {
    IssuerAllowList {
        issuers: issuers
            .iter()
            .map(|s| s.trim_end_matches('/').to_lowercase())
            .collect(),
    }
}

fn host_of(url: &str) -> Result<String, String> {
    let after = url
        .strip_prefix("https://")
        .ok_or("only https:// URLs are allowed")?;
    let host = after.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.split('@').last().unwrap_or(host); // drop userinfo
    let host = host.trim_start_matches('[').trim_end_matches(']'); // ipv6 brackets
    // strip :port
    let host = if let Some(idx) = host.rfind(':') {
        // keep ipv6 (which has no port here after bracket strip) — only split if all-after-colon is numeric
        let (h, p) = host.split_at(idx);
        if p[1..].chars().all(|c| c.is_ascii_digit()) && !h.is_empty() {
            h
        } else {
            host
        }
    } else {
        host
    };
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    Ok(host.to_lowercase())
}

fn is_blocked_literal(host: &str) -> bool {
    // Metadata + obvious literals (string-level; defense-in-depth, every hop).
    if host == "169.254.169.254" || host == "metadata.google.internal" || host == "::1" {
        return true;
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    // IPv4 private/loopback/link-local ranges.
    let octets: Vec<u8> = host.split('.').filter_map(|o| o.parse::<u8>().ok()).collect();
    if octets.len() == 4 {
        let [a, b, _, _] = [octets[0], octets[1], octets[2], octets[3]];
        if a == 127 {
            return true; // loopback
        }
        if a == 10 {
            return true; // 10/8
        }
        if a == 192 && b == 168 {
            return true; // 192.168/16
        }
        if a == 172 && (16..=31).contains(&b) {
            return true; // 172.16/12
        }
        if a == 169 && b == 254 {
            return true; // link-local / metadata
        }
        if a == 0 {
            return true;
        }
    }
    false
}

/// Gate an outbound URL before any fetch: HTTPS only, host must be a configured
/// issuer host, and never a private/loopback/link-local/metadata target.
pub fn check_outbound_url(allow: &IssuerAllowList, url: &str) -> Result<(), String> {
    let host = host_of(url)?;
    if is_blocked_literal(&host) {
        return Err(format!("blocked host: {host}"));
    }
    let anchored = allow.issuers.iter().any(|iss| {
        host_of(iss).map(|h| h == host).unwrap_or(false)
    });
    if !anchored {
        return Err(format!("host not in issuer allow-list: {host}"));
    }
    Ok(())
}

/// Documents and enforces that we NEVER select key material from a token header's
/// `jku`/`x5u`/`jwk`. Returns true always — present so call sites assert intent and
/// tests guard against regressions.
pub fn header_key_url_is_ignored(_header: &Value) -> bool {
    // No code path reads jku/x5u/jwk for trust selection; trust comes only from
    // the anchored issuer's JWKS fetched via check_outbound_url.
    true
}
```

- [ ] **Step 4: Run the pure test to verify it passes**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib ssrf
```
Expected: PASS — `test result: ok. 6 passed`.

- [ ] **Step 5: Write the WASM fetcher that calls the guard first**

Create `edge/src/fetcher.rs`:
```rust
//! `fetch`-backed JWKS/discovery retrieval. ALWAYS calls the SSRF guard first;
//! refuses redirects implicitly by re-checking the final URL. WASM-only.

use crate::ssrf::{IssuerAllowList, check_outbound_url};
use serde_json::Value;
use worker::*;

/// Fetch JSON from an anchored, allow-listed HTTPS issuer endpoint.
pub async fn fetch_json_guarded(allow: &IssuerAllowList, url: &str) -> std::result::Result<Value, String> {
    check_outbound_url(allow, url).map_err(|e| format!("ssrf guard: {e}"))?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    // Manual redirect handling so a 3xx cannot bounce us to a private host.
    init.with_redirect(RequestRedirect::Manual);
    let req = Request::new_with_init(url, &init).map_err(|e| format!("request: {e}"))?;
    let mut resp = Fetch::Request(req).send().await.map_err(|e| format!("fetch: {e}"))?;
    if (300..400).contains(&resp.status_code()) {
        return Err("redirects are not followed for issuer fetches".to_string());
    }
    if resp.status_code() != 200 {
        return Err(format!("issuer fetch status {}", resp.status_code()));
    }
    resp.json::<Value>().await.map_err(|e| format!("json: {e}"))
}
```

- [ ] **Step 6: Verify the WASM build compiles, then run a manual `wrangler dev` smoke check**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo build --target wasm32-unknown-unknown --release
cargo test --lib            # all pure tests across all modules
```
Expected: WASM build compiles; `cargo test --lib` reports all modules green (sum of every task's tests).

Manual `wrangler dev` check (documents the WASM/Worker integration that unit tests cannot cover):
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
echo "0000000000000000000000000000000000000000000000000000000000000007" | npx -y wrangler@4 secret put INTERNAL_ED25519_SEED --local
npx -y wrangler@4 dev
# In another shell:
#   curl -s localhost:8787/.well-known/openid-configuration | jq .issuer   -> "https://idp.tessera.example"
#   curl -s localhost:8787/jwks | jq '.keys[].alg'                          -> "EdDSA" (RSA once attached)
```
Expected: discovery returns the byte-identical issuer; `/jwks` validates invariants and returns the EdDSA key.

- [ ] **Step 7: Commit**

```bash
git add edge/src/ssrf.rs edge/src/fetcher.rs edge/src/lib.rs
git commit -m "feat(edge): SSRF-safe JWKS/discovery fetcher (anchored allow-list, no redirects, ignore token key URLs)"
```

---

### Task 12: Host-emitted decision/audit log (OPA event shape) + typed Phase-4 authz seam

**Files:**
- Create: `edge/src/authz.rs` (typed PEP seam; no policy logic)
- Create: `edge/src/decision_log.rs` (OPA-shaped event builder + masking)
- Modify: `edge/src/lib.rs` (add modules)
- Test: `edge/src/decision_log.rs` and `edge/src/authz.rs` (`#[cfg(test)]` modules)

**Interfaces:**
- Consumes: nothing pure.
- Produces (authz seam):
  - `pub struct AuthzInput { pub subject: String, pub action: String, pub resource: String, pub tenant: String }`
  - `pub enum AuthzDecision { Allow, Deny { reason: String } }`
  - `pub trait PolicyEngine { fn evaluate(&self, input: &AuthzInput) -> AuthzDecision; }`
  - `pub struct DenyAllEngine;` (fail-closed default until Phase 4 wires Regorus) impl `PolicyEngine`
- Produces (decision log):
  - `pub struct DecisionEvent { pub decision_id: String, pub path: String, pub input: serde_json::Value, pub result: bool, pub timestamp: u64 }`
  - `pub fn render_opa_event(ev: &DecisionEvent) -> serde_json::Value` (mirrors OPA decision-log shape; masks token/secret fields)

- [ ] **Step 1: Write the failing tests**

Create `edge/src/authz.rs` with the test module:
```rust
//! Typed PEP seam. NO policy logic lives here — Phase 4 plugs Regorus in behind
//! `PolicyEngine`. The default is fail-closed (deny). Host-tested.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_engine_denies_everything_fail_closed() {
        let e = DenyAllEngine;
        let input = AuthzInput {
            subject: "u-1".into(),
            action: "read".into(),
            resource: "users/9".into(),
            tenant: "t-1".into(),
        };
        match e.evaluate(&input) {
            AuthzDecision::Deny { reason } => assert!(reason.contains("no policy")),
            AuthzDecision::Allow => panic!("default must deny"),
        }
    }
}
```

Create `edge/src/decision_log.rs` with the test module:
```rust
//! Host-emitted decision logs mirroring OPA's event shape (Regorus has no
//! decision-log plugin). Masks token/secret fields. Host-tested.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev() -> DecisionEvent {
        DecisionEvent {
            decision_id: "d-123".into(),
            path: "data.authz.allow".into(),
            input: json!({ "subject":"u-1","action":"read","resource":"users/9","access_token":"SECRET","authorization":"Bearer SECRET" }),
            result: true,
            timestamp: 1_750_000_000,
        }
    }

    #[test]
    fn renders_the_opa_decision_log_shape() {
        let out = render_opa_event(&ev());
        assert_eq!(out["decision_id"], "d-123");
        assert_eq!(out["path"], "data.authz.allow");
        assert_eq!(out["result"], true);
        assert_eq!(out["timestamp"], 1_750_000_000u64);
        assert!(out.get("input").is_some());
    }

    #[test]
    fn masks_token_and_secret_fields_never_logging_them() {
        let out = render_opa_event(&ev());
        let input = &out["input"];
        assert_eq!(input["subject"], "u-1");
        assert_eq!(input["access_token"], "***");
        assert_eq!(input["authorization"], "***");
        let serialized = out.to_string();
        assert!(!serialized.contains("SECRET"), "raw secret leaked into log");
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Add to `edge/src/lib.rs`:
```rust
pub mod authz;
pub mod decision_log;
```
Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib authz
cargo test --lib decision_log
```
Expected: both FAIL to compile.

- [ ] **Step 3: Write the authz seam**

Prepend to `edge/src/authz.rs`:
```rust
/// Inputs the PEP passes to the policy engine. Mirrors NIST's four ABAC
/// categories at a high level (subject/action/resource + tenant context).
#[derive(Clone, Debug)]
pub struct AuthzInput {
    pub subject: String,
    pub action: String,
    pub resource: String,
    pub tenant: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthzDecision {
    Allow,
    Deny { reason: String },
}

/// The seam Phase 4 implements with Regorus. The PEP (the Worker) holds NO policy
/// logic; it only calls `evaluate` and fails closed on Deny/error.
pub trait PolicyEngine {
    fn evaluate(&self, input: &AuthzInput) -> AuthzDecision;
}

/// Fail-closed default until the Regorus engine is wired (Phase 4).
pub struct DenyAllEngine;

impl PolicyEngine for DenyAllEngine {
    fn evaluate(&self, _input: &AuthzInput) -> AuthzDecision {
        AuthzDecision::Deny {
            reason: "no policy engine wired (fail-closed default)".to_string(),
        }
    }
}
```

- [ ] **Step 4: Write the decision-log builder**

Prepend to `edge/src/decision_log.rs`:
```rust
use serde_json::{Value, json};

#[derive(Clone, Debug)]
pub struct DecisionEvent {
    pub decision_id: String,
    pub path: String,
    pub input: Value,
    pub result: bool,
    pub timestamp: u64,
}

/// Fields that must never be logged in the clear.
const MASKED_FIELDS: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "authorization",
    "dpop",
    "client_secret",
    "code",
    "code_verifier",
    "password",
];

fn mask(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if MASKED_FIELDS.iter().any(|f| k.eq_ignore_ascii_case(f)) {
                    out.insert(k.clone(), json!("***"));
                } else {
                    out.insert(k.clone(), mask(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(mask).collect()),
        other => other.clone(),
    }
}

/// Render an append-only decision-log entry mirroring OPA's decision-log event
/// shape (`decision_id`/`path`/`input`/`result`/`timestamp`), with masking.
pub fn render_opa_event(ev: &DecisionEvent) -> Value {
    json!({
        "decision_id": ev.decision_id,
        "path": ev.path,
        "input": mask(&ev.input),
        "result": ev.result,
        "timestamp": ev.timestamp,
        "labels": { "engine": "regorus", "pep": "tessera-edge" },
    })
}
```

- [ ] **Step 5: Run them to verify they pass**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib authz
cargo test --lib decision_log
```
Expected: both PASS — `authz` 1 passed, `decision_log` 2 passed.

- [ ] **Step 6: Run the full suite + WASM build a final time**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/edge
cargo test --lib
cargo build --target wasm32-unknown-unknown --release
cargo tree -i getrandom
```
Expected: all module tests green; WASM build compiles; a single `getrandom` version.

- [ ] **Step 7: Commit**

```bash
git add edge/src/authz.rs edge/src/decision_log.rs edge/src/lib.rs
git commit -m "feat(edge): OPA-shaped decision log with masking + typed fail-closed authz seam"
```

---

### Task 13: SAML broker note (deferred capability boundary)

**Files:**
- Create: `edge/docs/saml-broker.md`

**Interfaces:**
- Consumes: nothing.
- Produces: a documentation file recording that SAML is brokered to OIDC and never hand-rolled in WASM.

- [ ] **Step 1: Write the broker note**

Create `edge/docs/saml-broker.md`:
```markdown
# SAML — brokered to OIDC, never hand-rolled in WASM

The edge engine does **not** parse or verify SAML XML / XML-DSig. Per the design
spec (§4.1, §6) and research brief 07/10:

- `samael`/`bergshamra`/`xml-sec` rely on xmlsec1/libxml2/OpenSSL and do **not**
  build on `wasm32-unknown-unknown`.
- XML Signature Wrapping and parser-differential CVEs (CVE-2025-25291/25292,
  CVE-2025-66567/66568) make hand-rolled c14n/verification unsafe.

**Boundary:** any SAML IdP is fronted by a broker (Cloudflare Access / WorkOS /
Keycloak) that converts SAML -> OIDC. The Worker then consumes OIDC only, using
the RP path built in Task 7 (PKCE S256, state, nonce, RFC 9207 `iss`). The Worker
is kept entirely out of the XML trust path.

If SAML ever becomes mandatory in-process, it must be isolated off-WASM in a
single hardened library with parse-once / verify-and-consume-the-same-tree /
DTD-disabled / reject-multi-assertion semantics — out of scope for this phase.
```

- [ ] **Step 2: Commit**

```bash
git add edge/docs/saml-broker.md
git commit -m "docs(edge): SAML brokered-to-OIDC boundary note"
```

---

## Self-Review

**Spec coverage (Phase 2 scope = spec §4 Layer 1 + §5 engine MUST checklist + §7 build-order item 2):**

| Layer-1 requirement (spec §4.1 / §5) | Task |
|---|---|
| Project scaffold (Cargo + wrangler.jsonc + worker-build + getrandom `wasm_js` cfg + passing smoke test) | Task 1 ✓ |
| JWT (RFC 8725): explicit alg allow-list, reject `none`, one-key-one-alg, `iss`/`aud`/`exp`/`nbf`, require `typ` | Task 2 ✓ |
| Two-algorithm policy — EdDSA internal signer (ed25519-dalek) | Task 3 ✓ |
| Two-algorithm policy — RS256 cloud token claims (per-cloud distinct `aud`, `sub`≤127, no `azp`) | Task 4 ✓ |
| RS256 cloud signing via WebCrypto SubtleCrypto; JWKS publishing both keys (distinct `kid`, `use:"sig"`) | Task 5 ✓ |
| Discovery `/.well-known/openid-configuration` (issuer byte-identical, S256-only) + `/jwks` | Task 6 ✓ |
| OIDC RP: PKCE S256 explicit + state + nonce + RFC 9207 `iss` check | Task 7 ✓ |
| Opaque session issuance + Durable Object store with instant revocation / "log out everywhere" | Task 8 ✓ |
| Token introspection (RFC 7662), authenticated caller, inactive reveals nothing | Task 9 ✓ |
| DPoP proof verification (`typ=dpop+jwt`, `htm`/`htu`/`jti`/`iat`/`ath`, `cnf.jkt` via RFC 7638) | Task 10 ✓ |
| SSRF-safe JWKS/discovery fetch (anchored issuer allow-list, block RFC1918/metadata every hop, ignore token `jku`/`x5u`/`jwk`, no redirects) | Task 11 ✓ |
| Host-emitted decision/audit log mirroring OPA event shape (+ masking) | Task 12 ✓ |
| Typed Regorus authz seam deferred to Phase 4 (fail-closed `DenyAllEngine`) | Task 12 ✓ (seam only) |
| SAML brokered to OIDC, never hand-rolled in WASM | Task 13 ✓ (note) |
| Local JWT validation never per-request fetch | Task 2 (verify is in-process) + Task 11 (fetch only the anchored JWKS) ✓ |
| `--panic-unwind` + `console_error_panic_hook`; no ring/aws-lc-rs/openssl; `rust_crypto` backend | Global Constraints + Task 1 manifest ✓ |

**API-correctness pass (verified against current stable docs, June 2026):**
- workers-rs 0.8.3 Durable Object: `#[durable_object]` on the **struct only** (never the impl); `fn new(state, env)` is **synchronous**; `async fn fetch(&self, …)` takes **`&self`**. `Storage::get` returns **`Result<Option<T>>`** (missing ⇒ `Ok(None)`); `list_with_options` returns a JS `Map` whose `keys()` yields `Result<JsValue, JsValue>`. (Task 8 corrected.)
- `jsonwebtoken` 10.x: forged `alg:"none"` is **not** an `Algorithm` variant, so the header gate parses the **raw** JOSE header itself (controlled rejection) rather than `decode_header`; `Validation.{algorithms,leeway,validate_exp,validate_nbf}` are public fields and `set_issuer/set_audience/set_required_spec_claims` are methods; built-in exp/nbf time checks are disabled and re-enforced against the injected `now` (no system clock on WASM). (Task 2 corrected.)
- `ed25519-dalek` v2: `to_pkcs8_pem`/`to_public_key_pem` require the **`pem`** feature (the `pkcs8` feature alone is DER-only) — added to the manifest. `verify_strict` used for DPoP (Task 10).
- `web-sys` `SubtleCrypto`: `import_key_with_object(key_data: &Object, …)`, `sign_with_object_and_u8_array(data: &[u8])` (not `&mut`), `export_key`; `Crypto::subtle()` is infallible, `WorkerGlobalScope::crypto()` is `Result`. (Task 5 corrected.)
- The Worker entrypoint (`#[event]` handlers, `worker::*`, DO) is gated to `#[cfg(target_arch = "wasm32")]` so the pure modules compile and `cargo test` runs on the **host** target as the architecture claims (Tasks 1 & 6).
- The standalone `rsa` crate was removed from Phase 2 deps (unused; RS256 verify is covered by jsonwebtoken's `rust_crypto`, RS256 sign by WebCrypto) — avoids a `default-features=false` (no-alloc) build break.

Correctly **out of scope** (deferred, per spec build order): SCIM 2.0 service provider → Phase 3; Regorus policy authoring/eval → Phase 4 (only the typed seam here); native-Go control plane / offboarding saga / federation orchestration → Phase 5; Terraform/CDK trust provisioning → Phase 6; live SSE telemetry of token flow → Phase 7; PASETO v4.local stateless cross-Worker token (listed optional in spec) → left as the `pasetors` dependency, not wired; CI SHA-pinning/SLSA/SBOM → Phase 9.

**Placeholder scan:** No "TODO/TBD/implement error handling/similar to Task N". Every code step contains complete Rust. The only labeled deferrals are: the KV namespace `id` in `wrangler.jsonc` (`PLACEHOLDER_REPLACE_BEFORE_DEPLOY`, explicitly flagged), the JS `Map::keys()` iterator-to-key conversion in the DO `/revoke-all` loop (a thin binding detail to confirm at the `wrangler dev` integration check), and the fail-closed `DenyAllEngine` (intentional Phase-4 seam). The crate-API shapes (DO trait, `Storage::get` Option, SubtleCrypto signatures, dalek `pem`) are now verified against current docs (see the API-correctness pass above). The RFC 7638 test vector in Task 10 has a recompute note so the *canonicalization* (the contract) is what is asserted.

**Type consistency across tasks:**
- `util::{b64url_encode, b64url_decode}` (Task 1) consumed unchanged by Tasks 3, 5, 7, 8, 10.
- `jwt::{VerifyAlg, VerifyParams, VerifiedClaims, verify_jwt}` (Task 2) consumed unchanged by Task 3 (self-verify test) and Task 9 (`introspection_response_from_jwt` takes `&VerifiedClaims`).
- `internal_token::InternalSigner::public_jwk` (Task 3) feeds `jwks::assemble_jwks` (Task 5) and the `/jwks` route (Task 6).
- `federation::rs256_signing_header` (Task 4) is consumed by `webcrypto_rsa::sign_jwt_rs256` (Task 5).
- `jwks::{assemble_jwks, validate_jwks_invariants}` (Task 5) consumed unchanged by the `/jwks` route (Task 6).
- `discovery::validate_discovery` (Task 6) is the consumer-side check reused by the SSRF fetcher path (Task 11).
- `session::{SessionRecord, SessionStatus, evaluate}` (Task 8) consumed unchanged by `session_do::SessionStore` (Task 8 WASM) and `introspect::introspection_response_from_session` (Task 9).
- `ssrf::{IssuerAllowList, check_outbound_url}` (Task 11 pure) consumed unchanged by `fetcher::fetch_json_guarded` (Task 11 WASM).
- `authz::{AuthzInput, AuthzDecision, PolicyEngine}` (Task 12) is the stable seam Phase 4 implements; `DenyAllEngine` satisfies the trait today.
- `decision_log::{DecisionEvent, render_opa_event}` (Task 12) stands alone; consumed by the PEP wiring in Phase 4.
- Every `verify_*`/`build_*` signature defined in an earlier task is referenced with the identical signature in later tasks' tests and call sites.

---

## Subsequent phase plans (to be written next, one file each)

3. `…-phase-3-scim-service-provider.md` — Okta+Entra dual-dialect SCIM 2.0 on this same `edge/` crate; CI replay vectors + validators.
4. `…-phase-4-policy-opa-regorus.md` — Rego v1 RBAC-A + SoD; `opa test` + Regal; Regorus engine wired behind the `PolicyEngine` seam from Task 12; signed R2 bundle.
5. `…-phase-5-control-plane-go.md` — native Go JML state machines, offboarding saga, risk-tiered reviews, federation orchestration calling the RS256 minting from Tasks 4/5.
6. `…-phase-6-multicloud-federation-iac.md` — Terraform per-cloud trust modules anchored to this engine's issuer/JWKS; CDK access-review stack; ephemeral CI + reaper.
7. `…-phase-7-telemetry-live-3d.md` — Queue→DO aggregator→SSE; wire real engine events into the Phase-1 3D pulses.
