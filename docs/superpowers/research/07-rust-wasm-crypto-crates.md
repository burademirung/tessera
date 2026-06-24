# Rust Crate Set for Identity Engine on Cloudflare Workers (wasm32-unknown-unknown)

## The governing rule
Workers Rust compiles to `wasm32-unknown-unknown`: **C/asm crypto won't build** → no `ring`, `aws-lc-rs`, `boring`, `openssl` (or anything depending on them). Pure-Rust (RustCrypto, dalek) builds. **Randomness must be wired:** getrandom 0.3/0.4 feature `wasm_js` **AND** `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'` (both required); 0.2 = feature `js`. Routes to `crypto.getRandomValues`. **Run `cargo tree -i getrandom`** before deploy and unify versions — #1 cause of broken builds (often transitive).

## JWT/JOSE
`jsonwebtoken` 10.4 (`default-features=false`, features `use_pem`,`rust_crypto`) — EdDSA + RS256 + `jwk` module (models + RFC 7638 `thumbprint()`). **10.x requires explicit backend** (`aws_lc_rs` = C, won't build → use `rust_crypto`). Avoid josekit (OpenSSL), jwt/rust-jwt, jose-rs (pre-alpha). jwt-simple works only with `pure-rust` feature.

## Ed25519 / RSA / WebCrypto
`ed25519-dalek` v2.2 (pure Rust, `verify_strict`, zeroize) for internal signing + DPoP keys. RSA **verify-only** via the `rsa` crate is fine (federation tokens, public key). **RSA sign/keygen → WebCrypto SubtleCrypto** (the `rsa` crate carries RUSTSEC-2023-0071 Marvin timing attack; pure-Rust wasm keygen is slow). Access via `js_sys::global()` → `web_sys::WorkerGlobalScope` → `.crypto()?.subtle()`, await with `JsFuture`; web-sys features `WorkerGlobalScope`,`Crypto`,`SubtleCrypto`,`CryptoKey`,`CryptoKeyPair`.

## JWKS + thumbprints
Use jsonwebtoken's `jwk` module (models + RFC 7638 thumbprint). Note: jose-jwk's `Thumbprint` is X.509 (`x5t`), NOT RFC 7638.

## PASETO / DPoP
`pasetors` 0.7.8 v4.local (pure Rust orion+ed25519-compact; wire getrandom). Avoid rusty_paseto (`ring`). DPoP = roll your own (signed JWT: `typ=dpop+jwt`, embedded `jwk`, `jti`/`htm`/`htu`/`iat`/`ath`; verify sig + htm/htu + iat + single-use jti + thumbprint==`cnf.jkt`).

## SAML XML-DSig — DO NOT in WASM
samael (xmlsec1/libxml2/OpenSSL — won't build), bergshamra (young, unverified on wasm), xml-sec (not production). C14N bugs → XSW. **Prefer OIDC; if SAML mandatory, isolate off-wasm or broker SAML→OIDC** (Cloudflare Access/WorkOS/Keycloak); keep Worker out of the XML trust path.

## OIDC RP / OAuth2
`oauth2` 5.0 + `openidconnect` 4.0 (both `default-features=false`) with a thin `AsyncHttpClient` over workers-rs `fetch`. PKCE `PkceCodeChallenge::new_random_sha256()`; `CoreJwsSigningAlgorithm` covers RS256/ES256/EdDSA. Never pull reqwest/native-TLS.

## Regorus / workers-rs
`regorus` 0.10 (`default-features=false`, features `arc`,`regex`,`semver` + à la carte `base64`/`glob`/`jsonschema`; **omit** `std`,`time`,`rand`,`http`,`net`,`mimalloc`). Deterministic — inject time/random/http as input/data. Embed: `Engine::new()`, `add_policy`, `add_data`, `set_input`, `eval_rule`; custom builtins via `add_extension`. `worker` 0.8.5: KV/DO(SQLite)/R2/Cron stable; D1/Queues/DO-RPC maturing; bundle 3 MB(Free)/10 MB(Paid); `--panic-unwind`.

## Cargo.toml sketch
```toml
worker = { version="0.8", features=["http","d1"] }
worker-macros = "0.8"
web-sys = { version="0.3", features=["WorkerGlobalScope","Crypto","SubtleCrypto","CryptoKey","CryptoKeyPair"] }
jsonwebtoken = { version="10.4", default-features=false, features=["use_pem","rust_crypto"] }
ed25519-dalek = { version="2.2", default-features=false, features=["rand_core","pkcs8","zeroize"] }
pasetors = { version="0.7", default-features=false, features=["std","v4","paserk"] }
oauth2 = { version="5.0", default-features=false }
openidconnect = { version="4.0", default-features=false }
regorus = { version="0.10", default-features=false, features=["arc","regex","semver","base64","jsonschema"] }
sha2="0.10"; base64ct="1"; serde={version="1",features=["derive"]}; serde_json="1"
getrandom = { version="0.3", features=["wasm_js"] }
# .cargo/config.toml → [target.wasm32-unknown-unknown] rustflags=['--cfg','getrandom_backend="wasm_js"']
# NO: ring, aws-lc-rs, boring, openssl, josekit, rusty_paseto, samael, reqwest, tokio(full), rsa-for-signing
```
