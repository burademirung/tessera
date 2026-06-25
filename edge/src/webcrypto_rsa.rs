//! RS256 signing via the Worker's WebCrypto SubtleCrypto (the `rsa` crate is
//! verify-only here — RUSTSEC-2023-0071 Marvin timing). WASM-only.

use crate::util::b64url_encode;
use js_sys::{Object, Reflect, Uint8Array};
use serde_json::{json, Value};
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

fn rsa_pkcs1_algo() -> Object {
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
    let promise = subtle
        .import_key_with_object(
            "pkcs8",
            key_data.unchecked_ref::<Object>(),
            &rsa_pkcs1_algo(),
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
    let promise = subtle
        .sign_with_object_and_u8_array(&rsa_pkcs1_algo(), key, signing_input)
        .map_err(|e| format!("sign: {e:?}"))?;
    let result = JsFuture::from(promise)
        .await
        .map_err(|e| format!("sign await: {e:?}"))?;
    let buf = Uint8Array::new(&result);
    Ok(buf.to_vec())
}

/// Sign full claims into a compact JWS using the given header (Task 4).
pub async fn sign_jwt_rs256(
    key: &CryptoKey,
    header: &Value,
    claims: &Value,
) -> Result<String, String> {
    let h = b64url_encode(
        serde_json::to_vec(header)
            .map_err(|e| e.to_string())?
            .as_slice(),
    );
    let p = b64url_encode(
        serde_json::to_vec(claims)
            .map_err(|e| e.to_string())?
            .as_slice(),
    );
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
