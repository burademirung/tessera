//! Store-agnostic SCIM resource service: enforces dialect normalization, the
//! writable allow-list, atomic PATCH, soft-delete (active=false stays GET-able),
//! hard DELETE, and ETag/If-Match concurrency. The storage trait is implemented
//! over D1/DO in handlers.rs; tested here against an in-memory store.

use crate::scim::auth::TenantCtx;
use crate::scim::dialect::normalize_patch;
use crate::scim::error::{ScimError, ScimErrorType};
use crate::scim::model::{list_response, Meta, SCHEMA_USER};
use crate::scim::page::Page;
use crate::scim::patch::apply_patch;
use crate::scim::store::{apply_writable_allow_list, check_if_match, etag, USER_WRITABLE};
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct StoredUser {
    pub tenant: String,
    pub version: u64,
    pub body: Value,
}

pub trait UserStore {
    fn find_by_username(&self, tenant: &str, user_name: &str) -> Option<StoredUser>;
    fn find_by_external_id(&self, tenant: &str, external_id: &str) -> Option<StoredUser>;
    fn get(&self, tenant: &str, id: &str) -> Option<StoredUser>;
    fn list(&self, tenant: &str, page: &Page) -> (Vec<StoredUser>, usize);
    fn insert(&mut self, tenant: &str, id: &str, body: Value) -> StoredUser;
    fn replace(&mut self, tenant: &str, id: &str, body: Value) -> Option<StoredUser>;
    fn delete(&mut self, tenant: &str, id: &str) -> bool;
}

pub struct UserService<'a, S: UserStore> {
    pub store: &'a mut S,
    pub new_id: &'a dyn Fn() -> String,
    pub now: &'a dyn Fn() -> String,
}

pub type Outcome = (u16, Value, Option<String>);

impl<'a, S: UserStore> UserService<'a, S> {
    fn finalize(&self, mut su: StoredUser) -> Outcome {
        let id = su.body["id"].as_str().unwrap_or_default().to_string();
        // ETag MUST be reproducible across reads: hash the STABLE resource content
        // (the stored body with volatile meta removed) keyed by the monotonic
        // version. `last_modified`/`location` are added to the response AFTER
        // hashing, so a fresh GET reproduces the exact same ETag (otherwise every
        // If-Match would 412 once `now()` is the real clock, not a test constant).
        let mut stable = su.body.clone();
        if let Some(obj) = stable.as_object_mut() {
            obj.remove("meta");
        }
        let tag = etag(su.version, &stable);
        let meta = Meta {
            resource_type: Some("User".into()),
            created: su.body["meta"]["created"].as_str().map(str::to_string),
            last_modified: Some((self.now)()),
            location: Some(format!("/scim/v2/Users/{id}")),
            version: Some(tag.clone()),
        };
        su.body["meta"] = serde_json::to_value(meta).unwrap();
        (200, su.body, Some(tag))
    }

    /// The reproducible ETag for a stored resource (same input `finalize` hashes).
    fn etag_of(&self, su: &StoredUser) -> String {
        let mut stable = su.body.clone();
        if let Some(obj) = stable.as_object_mut() {
            obj.remove("meta");
        }
        etag(su.version, &stable)
    }

    pub fn create(&mut self, ctx: &TenantCtx, incoming: Value) -> Result<Outcome, ScimError> {
        let mut clean = apply_writable_allow_list(&incoming, USER_WRITABLE);
        let user_name = clean["userName"].as_str().ok_or_else(|| {
            ScimError::bad_request(ScimErrorType::InvalidValue, "userName is required")
        })?;
        // De-dup by userName AND externalId.
        if self.store.find_by_username(&ctx.tenant_id, user_name).is_some() {
            return Err(ScimError::conflict("userName already exists"));
        }
        if let Some(ext) = clean["externalId"].as_str() {
            if self.store.find_by_external_id(&ctx.tenant_id, ext).is_some() {
                return Err(ScimError::conflict("externalId already exists"));
            }
        }
        let id = (self.new_id)();
        clean["id"] = json!(id);
        if clean["schemas"].as_array().map_or(true, |a| a.is_empty()) {
            clean["schemas"] = json!([SCHEMA_USER]);
        }
        clean["meta"] = json!({ "created": (self.now)() });
        let su = self.store.insert(&ctx.tenant_id, &id, clean);
        let (_, body, tag) = self.finalize(su);
        Ok((201, body, tag))
    }

    pub fn get(&self, ctx: &TenantCtx, id: &str) -> Result<Outcome, ScimError> {
        let su = self
            .store
            .get(&ctx.tenant_id, id)
            .ok_or_else(|| ScimError::not_found("user not found"))?;
        Ok(self.finalize(su))
    }

    pub fn list(&self, ctx: &TenantCtx, page: &Page) -> Outcome {
        let (rows, total) = self.store.list(&ctx.tenant_id, page);
        let resources: Vec<Value> = rows
            .into_iter()
            .map(|su| self.finalize(su).1)
            .collect();
        let n = resources.len();
        (200, list_response(resources, total, page.start_index, n), None)
    }

    pub fn replace(
        &mut self,
        ctx: &TenantCtx,
        id: &str,
        incoming: Value,
        if_match: Option<&str>,
    ) -> Result<Outcome, ScimError> {
        let existing = self
            .store
            .get(&ctx.tenant_id, id)
            .ok_or_else(|| ScimError::not_found("user not found"))?;
        check_if_match(if_match, &self.etag_of(&existing))?;
        let mut clean = apply_writable_allow_list(&incoming, USER_WRITABLE);
        clean["id"] = json!(id);
        clean["meta"] = json!({ "created": existing.body["meta"]["created"].clone() });
        let su = self
            .store
            .replace(&ctx.tenant_id, id, clean)
            .ok_or_else(|| ScimError::not_found("user not found"))?;
        Ok(self.finalize(su))
    }

    pub fn patch(
        &mut self,
        ctx: &TenantCtx,
        id: &str,
        body: Value,
        if_match: Option<&str>,
    ) -> Result<Outcome, ScimError> {
        let existing = self
            .store
            .get(&ctx.tenant_id, id)
            .ok_or_else(|| ScimError::not_found("user not found"))?;
        check_if_match(if_match, &self.etag_of(&existing))?;
        let ops = normalize_patch(&body)?;
        let patched = apply_patch(&existing.body, &ops)?; // atomic
        // Re-apply allow-list: PATCH must not let a client set server-owned fields.
        let mut clean = apply_writable_allow_list(&patched, USER_WRITABLE);
        clean["id"] = json!(id);
        clean["meta"] = json!({ "created": existing.body["meta"]["created"].clone() });
        let su = self
            .store
            .replace(&ctx.tenant_id, id, clean)
            .ok_or_else(|| ScimError::not_found("user not found"))?;
        Ok(self.finalize(su))
    }

    /// Hard DELETE — only honored on explicit DELETE (Entra hard removal).
    pub fn delete(&mut self, ctx: &TenantCtx, id: &str) -> Result<Outcome, ScimError> {
        if self.store.delete(&ctx.tenant_id, id) {
            Ok((204, Value::Null, None))
        } else {
            Err(ScimError::not_found("user not found"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scim::auth::TenantCtx;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MemStore {
        // key: (tenant, id)
        rows: HashMap<(String, String), StoredUser>,
    }
    impl UserStore for MemStore {
        fn find_by_username(&self, tenant: &str, user_name: &str) -> Option<StoredUser> {
            self.rows.values().find(|s| {
                s.tenant == tenant && s.body["userName"].as_str() == Some(user_name)
            }).cloned()
        }
        fn find_by_external_id(&self, tenant: &str, external_id: &str) -> Option<StoredUser> {
            self.rows.values().find(|s| {
                s.tenant == tenant && s.body["externalId"].as_str() == Some(external_id)
            }).cloned()
        }
        fn get(&self, tenant: &str, id: &str) -> Option<StoredUser> {
            self.rows.get(&(tenant.to_string(), id.to_string())).cloned()
        }
        fn list(&self, tenant: &str, _page: &Page) -> (Vec<StoredUser>, usize) {
            let mut v: Vec<StoredUser> =
                self.rows.values().filter(|s| s.tenant == tenant).cloned().collect();
            v.sort_by(|a, b| a.body["id"].as_str().cmp(&b.body["id"].as_str()));
            let total = v.len();
            (v, total)
        }
        fn insert(&mut self, tenant: &str, id: &str, body: Value) -> StoredUser {
            let su = StoredUser { tenant: tenant.into(), version: 1, body };
            self.rows.insert((tenant.into(), id.into()), su.clone());
            su
        }
        fn replace(&mut self, tenant: &str, id: &str, body: Value) -> Option<StoredUser> {
            let key = (tenant.to_string(), id.to_string());
            let prev = self.rows.get(&key)?;
            let su = StoredUser { tenant: tenant.into(), version: prev.version + 1, body };
            self.rows.insert(key, su.clone());
            Some(su)
        }
        fn delete(&mut self, tenant: &str, id: &str) -> bool {
            self.rows.remove(&(tenant.to_string(), id.to_string())).is_some()
        }
    }

    fn ctx() -> TenantCtx {
        TenantCtx { tenant_id: "t1".into(), scopes: vec!["scim".into()] }
    }
    fn svc(store: &mut MemStore) -> UserService<'_, MemStore> {
        UserService { store, new_id: &|| "id-1".to_string(), now: &|| "2026-06-24T00:00:00Z".to_string() }
    }

    #[test]
    fn create_returns_201_and_server_id() {
        let mut s = MemStore::default();
        let (status, body, tag) =
            svc(&mut s).create(&ctx(), json!({ "userName": "a", "id": "client-tried" })).unwrap();
        assert_eq!(status, 201);
        assert_eq!(body["id"], "id-1");        // server-assigned, client value ignored
        assert!(tag.unwrap().starts_with("W/\""));
    }

    #[test]
    fn duplicate_username_is_409() {
        let mut s = MemStore::default();
        svc(&mut s).create(&ctx(), json!({ "userName": "a" })).unwrap();
        let err = svc(&mut s).create(&ctx(), json!({ "userName": "a" })).unwrap_err();
        assert_eq!(err.status, 409);
        assert_eq!(err.scim_type, Some(ScimErrorType::Uniqueness));
    }

    #[test]
    fn soft_delete_via_patch_keeps_user_gettable() {
        let mut s = MemStore::default();
        svc(&mut s).create(&ctx(), json!({ "userName": "a" })).unwrap();
        // Entra capitalized + string active.
        let (status, body, _) = svc(&mut s).patch(
            &ctx(), "id-1",
            json!({ "Operations": [{ "op": "Replace", "value": { "active": "False" } }] }),
            None,
        ).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body["active"], json!(false));
        // Still GET-able (soft delete).
        let (gstatus, gbody, _) = svc(&mut s).get(&ctx(), "id-1").unwrap();
        assert_eq!(gstatus, 200);
        assert_eq!(gbody["active"], json!(false));
    }

    #[test]
    fn put_replace_then_if_match_mismatch_is_412() {
        let mut s = MemStore::default();
        let (_, _, tag) = svc(&mut s).create(&ctx(), json!({ "userName": "a" })).unwrap();
        let good = tag.unwrap();
        // First PUT with correct ETag succeeds and bumps version.
        svc(&mut s).replace(&ctx(), "id-1", json!({ "userName": "a", "displayName": "X" }), Some(&good)).unwrap();
        // Stale ETag now fails.
        let err = svc(&mut s).replace(
            &ctx(), "id-1", json!({ "userName": "a", "displayName": "Y" }), Some(&good),
        ).unwrap_err();
        assert_eq!(err.status, 412);
    }

    #[test]
    fn hard_delete_removes_and_then_404() {
        let mut s = MemStore::default();
        svc(&mut s).create(&ctx(), json!({ "userName": "a" })).unwrap();
        let (status, _, _) = svc(&mut s).delete(&ctx(), "id-1").unwrap();
        assert_eq!(status, 204);
        assert_eq!(svc(&mut s).get(&ctx(), "id-1").unwrap_err().status, 404);
    }

    #[test]
    fn list_of_empty_is_200_empty_listresponse() {
        let s = &mut MemStore::default();
        let page = Page { start_index: 1, count: 100 };
        let (status, body, _) = svc(s).list(&ctx(), &page);
        assert_eq!(status, 200);
        assert_eq!(body["totalResults"], json!(0));
        assert_eq!(body["Resources"], json!([]));
    }

    #[test]
    fn patch_cannot_set_server_owned_id() {
        let mut s = MemStore::default();
        svc(&mut s).create(&ctx(), json!({ "userName": "a" })).unwrap();
        let (_, body, _) = svc(&mut s).patch(
            &ctx(), "id-1",
            json!({ "Operations": [{ "op": "replace", "value": { "id": "hijack", "displayName": "ok" } }] }),
            None,
        ).unwrap();
        assert_eq!(body["id"], "id-1");          // id unchanged
        assert_eq!(body["displayName"], "ok");   // legit field applied
    }
}
