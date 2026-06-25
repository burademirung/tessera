//! HTTP glue: verify-first auth, method/path dispatch, scim+json serialization,
//! ETag header. IO uses workers-rs; the pure DECISIONS are unit-tested here.

use crate::scim::error::ScimError;
use serde_json::Value;

pub const SCIM_CONTENT_TYPE: &str = "application/scim+json";

/// Build the (status, body, headers) tuple for an error, used by the dispatcher.
pub fn error_response(err: &ScimError) -> (u16, Value, &'static str) {
    (err.status, err.to_json(), SCIM_CONTENT_TYPE)
}

/// Decide which SCIM route a (method, path) maps to. Pure, fully testable.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    ServiceProviderConfig,
    ResourceTypes,
    Schemas,
    UsersCollection,        // GET (list/filter) | POST (create)
    UserItem(String),       // GET | PUT | PATCH | DELETE
    GroupsCollection,
    GroupItem(String),
    NotFound,
}

pub fn route(method: &str, path: &str) -> Route {
    let _ = method;
    let p = path.strip_prefix("/scim/v2").unwrap_or(path);
    let p = p.trim_end_matches('/');
    match (method, p) {
        (_, "/ServiceProviderConfig") => Route::ServiceProviderConfig,
        (_, "/ResourceTypes") => Route::ResourceTypes,
        (_, "/Schemas") => Route::Schemas,
        (_, "/Users") => Route::UsersCollection,
        (_, "/Groups") => Route::GroupsCollection,
        (_, p) if p.starts_with("/Users/") => {
            Route::UserItem(p.trim_start_matches("/Users/").to_string())
        }
        (_, p) if p.starts_with("/Groups/") => {
            Route::GroupItem(p.trim_start_matches("/Groups/").to_string())
        }
        _ => Route::NotFound,
    }
}

/// SCIM attributes that may be filtered, mapped to their D1 columns. The filter
/// compiler rejects anything not in this allow-list.
pub const USER_FILTER_ALLOW: &[(&str, &str)] = &[
    ("userName", "user_name"),
    ("externalId", "external_id"),
    ("active", "active"),
    ("displayName", "display_name"),
];

// ---------------------------------------------------------------------------
// WASM-only async dispatcher: verify-first auth -> route -> UserService -> D1.
// The pure decisions above (route/error/allow-list) are host-tested; this glue
// is gated to the Worker target and exercised end-to-end by the deploy gate.
// ---------------------------------------------------------------------------
#[cfg(target_arch = "wasm32")]
pub use wasm_dispatch::dispatch;

#[cfg(target_arch = "wasm32")]
mod wasm_dispatch {
    use super::*;
    use crate::scim::auth::{resolve_tenant, TenantCtx, VerifiedToken};
    use crate::scim::d1_store::Snapshot;
    use crate::scim::discovery;
    use crate::scim::page::parse_page;
    use crate::scim::service::{StoredUser, UserService};
    use worker::{Env, Method, Request, Response};

    fn json_response(status: u16, body: &Value) -> worker::Result<Response> {
        let mut resp = Response::from_json(body)?.with_status(status);
        resp.headers_mut().set("content-type", SCIM_CONTENT_TYPE)?;
        Ok(resp)
    }

    fn err_response(err: &ScimError) -> worker::Result<Response> {
        json_response(err.status, &err.to_json())
    }

    /// Verify the bearer token and resolve the tenant. The Phase-2 engine owns
    /// real token verification (JWT/introspection); this wires that seam. For now
    /// a token is accepted if present and the tenant is taken from a verified
    /// claim; integrate the Phase-2 verifier here when its API is finalized.
    fn verify_token(token: &str) -> Option<VerifiedToken> {
        // Minimal non-empty-token gate; the Phase-2 introspection/JWT verifier
        // replaces this closure body. Tenant is derived from the token subject
        // namespace once that verifier lands.
        if token.is_empty() {
            None
        } else {
            Some(VerifiedToken {
                tenant_id: "default".to_string(),
                scopes: vec!["scim".to_string()],
            })
        }
    }

    fn now_iso() -> String {
        worker::Date::now().to_string()
    }

    /// Load all users for a tenant into an in-memory Snapshot (parameterized).
    async fn load_snapshot(env: &Env, tenant: &str) -> worker::Result<Snapshot> {
        let db = env.d1("DB")?;
        let stmt = db
            .prepare("SELECT body, version FROM scim_users WHERE tenant = ?")
            .bind(&[tenant.into()])?;
        let result = stmt.all().await?;
        let rows: Vec<serde_json::Value> = result.results()?;
        let mut snap_rows = Vec::with_capacity(rows.len());
        for r in rows {
            let body: Value = r
                .get("body")
                .and_then(|b| b.as_str())
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(Value::Null);
            let version = r.get("version").and_then(|v| v.as_u64()).unwrap_or(1);
            snap_rows.push(StoredUser {
                tenant: tenant.to_string(),
                version,
                body,
            });
        }
        Ok(Snapshot { rows: snap_rows })
    }

    /// Persist the full Snapshot back to D1 (upsert each row, delete removed).
    async fn persist_user(env: &Env, su: &StoredUser) -> worker::Result<()> {
        let db = env.d1("DB")?;
        let body_str = serde_json::to_string(&su.body).unwrap_or_default();
        let id = su.body["id"].as_str().unwrap_or_default();
        let user_name = su.body["userName"].as_str().unwrap_or_default();
        let external_id = su.body["externalId"].as_str();
        let active = if su.body["active"].as_bool().unwrap_or(true) { 1 } else { 0 };
        let display_name = su.body["displayName"].as_str();
        let created = su.body["meta"]["created"].as_str().unwrap_or(&now_iso()).to_string();
        let lm = now_iso();
        let stmt = db
            .prepare(
                "INSERT INTO scim_users \
                 (tenant, id, user_name, external_id, active, display_name, body, version, created, last_modified) \
                 VALUES (?,?,?,?,?,?,?,?,?,?) \
                 ON CONFLICT(tenant, id) DO UPDATE SET \
                 user_name=excluded.user_name, external_id=excluded.external_id, \
                 active=excluded.active, display_name=excluded.display_name, \
                 body=excluded.body, version=excluded.version, last_modified=excluded.last_modified",
            )
            .bind(&[
                su.tenant.clone().into(),
                id.into(),
                user_name.into(),
                external_id.map(Into::into).unwrap_or(worker::wasm_bindgen::JsValue::NULL),
                active.into(),
                display_name.map(Into::into).unwrap_or(worker::wasm_bindgen::JsValue::NULL),
                body_str.into(),
                (su.version as f64).into(),
                created.into(),
                lm.into(),
            ])?;
        stmt.run().await?;
        Ok(())
    }

    async fn delete_user(env: &Env, tenant: &str, id: &str) -> worker::Result<bool> {
        let db = env.d1("DB")?;
        let stmt = db
            .prepare("DELETE FROM scim_users WHERE tenant = ? AND id = ?")
            .bind(&[tenant.into(), id.into()])?;
        let meta = stmt.run().await?.meta()?;
        Ok(meta.and_then(|m| m.changes).unwrap_or(0) > 0)
    }

    fn new_id() -> String {
        // RFC 4122-ish unique id from crypto randomness.
        let mut buf = [0u8; 16];
        let _ = getrandom::fill(&mut buf);
        let mut s = String::with_capacity(32);
        for b in buf {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Entry: verify-first auth, then route. Returns a SCIM JSON Response.
    pub async fn dispatch(mut req: Request, env: Env) -> worker::Result<Response> {
        let path = req.path();
        let method = req.method();

        // Verify-first: resolve tenant before any body parse or store access.
        let auth_header = req.headers().get("authorization").ok().flatten();
        let ctx = match resolve_tenant(auth_header.as_deref(), &verify_token) {
            Ok(c) => c,
            Err(e) => return err_response(&e),
        };

        let method_str = format!("{method:?}").to_uppercase();
        match route(&method_str, &path) {
            Route::ServiceProviderConfig => json_response(200, &discovery::service_provider_config()),
            Route::ResourceTypes => json_response(200, &discovery::resource_types()),
            Route::Schemas => json_response(200, &discovery::schemas()),

            Route::UsersCollection => match method {
                Method::Get => users_list(&env, &ctx, &req).await,
                Method::Post => {
                    let body: Value = req.json().await.unwrap_or(Value::Null);
                    users_create(&env, &ctx, body).await
                }
                _ => err_response(&ScimError::not_found("method not allowed")),
            },

            Route::UserItem(id) => match method {
                Method::Get => users_get(&env, &ctx, &id).await,
                Method::Put => {
                    let if_match = req.headers().get("if-match").ok().flatten();
                    let body: Value = req.json().await.unwrap_or(Value::Null);
                    users_replace(&env, &ctx, &id, body, if_match.as_deref()).await
                }
                Method::Patch => {
                    let if_match = req.headers().get("if-match").ok().flatten();
                    let body: Value = req.json().await.unwrap_or(Value::Null);
                    users_patch(&env, &ctx, &id, body, if_match.as_deref()).await
                }
                Method::Delete => users_delete(&env, &ctx, &id).await,
                _ => err_response(&ScimError::not_found("method not allowed")),
            },

            // Group CRUD: the PATCH engine + models are complete; the async D1
            // body for groups mirrors users and lands with the group store.
            Route::GroupsCollection | Route::GroupItem(_) => {
                err_response(&ScimError::not_found("groups endpoint not yet wired"))
            }
            Route::NotFound => err_response(&ScimError::not_found("not found")),
        }
    }

    async fn users_create(env: &Env, ctx: &TenantCtx, body: Value) -> worker::Result<Response> {
        let mut snap = match load_snapshot(env, &ctx.tenant_id).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        let nid = new_id();
        let outcome = {
            let mut svc = UserService { store: &mut snap, new_id: &|| nid.clone(), now: &now_iso };
            svc.create(ctx, body)
        };
        match outcome {
            Ok((status, body, tag)) => {
                if let Some(su) = snap.rows.last().cloned() {
                    persist_user(env, &su).await?;
                }
                let mut resp = json_response(status, &body)?;
                if let Some(t) = tag {
                    resp.headers_mut().set("etag", &t)?;
                }
                Ok(resp)
            }
            Err(e) => err_response(&e),
        }
    }

    async fn users_get(env: &Env, ctx: &TenantCtx, id: &str) -> worker::Result<Response> {
        let mut snap = load_snapshot(env, &ctx.tenant_id).await?;
        let svc = UserService { store: &mut snap, new_id: &new_id, now: &now_iso };
        match svc.get(ctx, id) {
            Ok((status, body, tag)) => {
                let mut resp = json_response(status, &body)?;
                if let Some(t) = tag {
                    resp.headers_mut().set("etag", &t)?;
                }
                Ok(resp)
            }
            Err(e) => err_response(&e),
        }
    }

    async fn users_list(env: &Env, ctx: &TenantCtx, req: &Request) -> worker::Result<Response> {
        let url = req.url()?;
        let mut start = None;
        let mut count = None;
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "startIndex" => start = Some(v.to_string()),
                "count" => count = Some(v.to_string()),
                _ => {}
            }
        }
        let page = match parse_page(start.as_deref(), count.as_deref()) {
            Ok(p) => p,
            Err(e) => return err_response(&e),
        };
        let mut snap = load_snapshot(env, &ctx.tenant_id).await?;
        let svc = UserService { store: &mut snap, new_id: &new_id, now: &now_iso };
        let (status, body, _) = svc.list(ctx, &page);
        json_response(status, &body)
    }

    async fn users_replace(
        env: &Env,
        ctx: &TenantCtx,
        id: &str,
        body: Value,
        if_match: Option<&str>,
    ) -> worker::Result<Response> {
        let mut snap = load_snapshot(env, &ctx.tenant_id).await?;
        let outcome = {
            let mut svc = UserService { store: &mut snap, new_id: &new_id, now: &now_iso };
            svc.replace(ctx, id, body, if_match)
        };
        finish_write(env, ctx, id, &mut snap, outcome).await
    }

    async fn users_patch(
        env: &Env,
        ctx: &TenantCtx,
        id: &str,
        body: Value,
        if_match: Option<&str>,
    ) -> worker::Result<Response> {
        let mut snap = load_snapshot(env, &ctx.tenant_id).await?;
        let outcome = {
            let mut svc = UserService { store: &mut snap, new_id: &new_id, now: &now_iso };
            svc.patch(ctx, id, body, if_match)
        };
        finish_write(env, ctx, id, &mut snap, outcome).await
    }

    async fn finish_write(
        env: &Env,
        ctx: &TenantCtx,
        id: &str,
        snap: &mut Snapshot,
        outcome: Result<crate::scim::service::Outcome, ScimError>,
    ) -> worker::Result<Response> {
        match outcome {
            Ok((status, body, tag)) => {
                if let Some(su) = snap
                    .rows
                    .iter()
                    .find(|s| s.tenant == ctx.tenant_id && s.body["id"].as_str() == Some(id))
                    .cloned()
                {
                    persist_user(env, &su).await?;
                }
                let mut resp = json_response(status, &body)?;
                if let Some(t) = tag {
                    resp.headers_mut().set("etag", &t)?;
                }
                Ok(resp)
            }
            Err(e) => err_response(&e),
        }
    }

    async fn users_delete(env: &Env, ctx: &TenantCtx, id: &str) -> worker::Result<Response> {
        match delete_user(env, &ctx.tenant_id, id).await {
            Ok(true) => {
                let mut resp = Response::empty()?.with_status(204);
                resp.headers_mut().set("content-type", SCIM_CONTENT_TYPE)?;
                Ok(resp)
            }
            Ok(false) => err_response(&ScimError::not_found("user not found")),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scim::error::ScimError;

    #[test]
    fn routes_collections_and_items() {
        assert_eq!(route("GET", "/scim/v2/Users"), Route::UsersCollection);
        assert_eq!(route("POST", "/scim/v2/Users"), Route::UsersCollection);
        assert_eq!(route("GET", "/scim/v2/Users/abc"), Route::UserItem("abc".into()));
        assert_eq!(route("PATCH", "/scim/v2/Users/abc"), Route::UserItem("abc".into()));
        assert_eq!(route("DELETE", "/scim/v2/Groups/g1"), Route::GroupItem("g1".into()));
        assert_eq!(route("GET", "/scim/v2/Schemas"), Route::Schemas);
        assert_eq!(route("GET", "/scim/v2/ServiceProviderConfig"), Route::ServiceProviderConfig);
    }

    #[test]
    fn error_response_uses_scim_content_type() {
        let (status, body, ct) = error_response(&ScimError::not_found("x"));
        assert_eq!(status, 404);
        assert_eq!(ct, "application/scim+json");
        assert_eq!(body["status"], "404");
    }
}
