//! `fetch`-backed JWKS/discovery retrieval. ALWAYS calls the SSRF guard first;
//! refuses redirects implicitly by re-checking the final URL. WASM-only.

use crate::ssrf::{check_outbound_url, IssuerAllowList};
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
