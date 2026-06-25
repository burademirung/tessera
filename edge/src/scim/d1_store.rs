//! D1-backed UserStore helpers. All queries are PARAMETERIZED (binds from the
//! filter compiler and pagination). The per-resource `version` is bumped on each
//! write so ETags advance monotonically.
//!
//! The injection-safe SQL builders + the in-memory `Snapshot` store are host-
//! testable (no `worker` dependency). The async D1 IO body of the dispatcher
//! lands in `handlers` under a `wasm32` gate and consumes a `Snapshot` loaded via
//! these builders.

use crate::scim::page::{to_sql, Page};
use crate::scim::service::{StoredUser, UserStore};
use serde_json::Value;

/// `SELECT body, version FROM scim_users WHERE tenant = ? AND (<where>) ORDER BY ...`.
/// `where_clause` comes from `filter::compile` (placeholders + binds) — never raw
/// input. Returns (sql, limit, offset); caller binds tenant + filter binds +
/// limit + offset in order.
pub fn select_by_filter_sql(where_clause: &str, page: &Page) -> (String, i64, i64) {
    let (order_limit, limit, offset) = to_sql(page);
    let sql = format!(
        "SELECT body, version FROM scim_users WHERE tenant = ? AND ({where_clause}) {order_limit}"
    );
    (sql, limit, offset)
}

pub fn count_by_filter_sql(where_clause: &str) -> String {
    format!("SELECT COUNT(*) AS n FROM scim_users WHERE tenant = ? AND ({where_clause})")
}

/// In-memory snapshot store used by the dispatcher (loaded from D1 via the
/// parameterized builders) and by the conformance test. Implements `UserStore`.
pub struct Snapshot {
    pub rows: Vec<StoredUser>,
}

impl UserStore for Snapshot {
    fn find_by_username(&self, tenant: &str, user_name: &str) -> Option<StoredUser> {
        self.rows
            .iter()
            .find(|s| s.tenant == tenant && s.body["userName"].as_str() == Some(user_name))
            .cloned()
    }
    fn find_by_external_id(&self, tenant: &str, external_id: &str) -> Option<StoredUser> {
        self.rows
            .iter()
            .find(|s| s.tenant == tenant && s.body["externalId"].as_str() == Some(external_id))
            .cloned()
    }
    fn get(&self, tenant: &str, id: &str) -> Option<StoredUser> {
        self.rows
            .iter()
            .find(|s| s.tenant == tenant && s.body["id"].as_str() == Some(id))
            .cloned()
    }
    fn list(&self, tenant: &str, _page: &Page) -> (Vec<StoredUser>, usize) {
        let v: Vec<StoredUser> = self
            .rows
            .iter()
            .filter(|s| s.tenant == tenant)
            .cloned()
            .collect();
        let n = v.len();
        (v, n)
    }
    fn insert(&mut self, tenant: &str, _id: &str, body: Value) -> StoredUser {
        let su = StoredUser {
            tenant: tenant.into(),
            version: 1,
            body,
        };
        self.rows.push(su.clone());
        su
    }
    fn replace(&mut self, tenant: &str, id: &str, body: Value) -> Option<StoredUser> {
        let row = self
            .rows
            .iter_mut()
            .find(|s| s.tenant == tenant && s.body["id"].as_str() == Some(id))?;
        row.version += 1;
        row.body = body;
        Some(row.clone())
    }
    fn delete(&mut self, tenant: &str, id: &str) -> bool {
        let before = self.rows.len();
        self.rows
            .retain(|s| !(s.tenant == tenant && s.body["id"].as_str() == Some(id)));
        self.rows.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_sql_is_parameterized_and_ordered() {
        let page = Page {
            start_index: 1,
            count: 50,
        };
        let (sql, limit, offset) = select_by_filter_sql("user_name = ?", &page);
        assert!(sql.contains("WHERE tenant = ?"));
        assert!(sql.contains("user_name = ?"));
        assert!(sql.contains("ORDER BY id ASC"));
        assert!(!sql.to_lowercase().contains("drop"));
        assert_eq!((limit, offset), (50, 0));
    }

    #[test]
    fn count_sql_is_parameterized() {
        let sql = count_by_filter_sql("external_id = ?");
        assert!(sql.starts_with("SELECT COUNT(*)"));
        assert!(sql.contains("tenant = ?"));
    }
}
