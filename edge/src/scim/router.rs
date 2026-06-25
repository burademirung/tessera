//! Mounts the SCIM service under /scim/v2 on the Phase-2 Worker entry.
//! `handle` is the single async entry the Phase-2 `fetch` dispatcher forwards
//! SCIM paths to. The crate's `lib.rs` uses a flat `match (method, path)` (no
//! `worker::Router`), so this forwarder takes `(Request, Env)` directly.

#[cfg(target_arch = "wasm32")]
pub async fn handle(req: worker::Request, env: worker::Env) -> worker::Result<worker::Response> {
    crate::scim::handlers::dispatch(req, env).await
}
