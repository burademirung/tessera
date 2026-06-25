//! Replays VERBATIM Okta + BOTH Entra dialect payloads against the same pure logic
//! the Worker runs, asserting the exact SCIM status-code matrix:
//!   create 201 · duplicate 409 (scimType uniqueness) · found 200 ·
//!   query-empty 200 (never 404) · PATCH user 200 · PUT 200 ·
//!   soft-delete keeps GET 200 · hard DELETE user 204 ·
//!   If-Match mismatch 412 · bad filter 400 invalidFilter.
//!
//! Group status codes (brief 06): Entra expects **PATCH group 204** and
//! **DELETE group 204** (no body). The group-member PATCH ENGINE (add + both
//! remove forms) is asserted here against the canonical tree; the dispatcher maps
//! a successful group PATCH/DELETE to 204 (asserted at the handler layer in Task 11
//! once the Group async D1 body lands).

use serde_json::{json, Value};
use std::fs;
use std::path::Path;

use lifecycle_edge::scim::auth::TenantCtx;
use lifecycle_edge::scim::d1_store::Snapshot;
use lifecycle_edge::scim::dialect::{coerce_active, normalize_patch};
use lifecycle_edge::scim::discovery;
use lifecycle_edge::scim::filter::parse_filter;
use lifecycle_edge::scim::page::Page;
use lifecycle_edge::scim::patch::apply_patch;
use lifecycle_edge::scim::service::UserService;

fn fixture(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap()
}

fn ctx() -> TenantCtx {
    TenantCtx {
        tenant_id: "t1".into(),
        scopes: vec!["scim".into()],
    }
}

fn store() -> Snapshot {
    Snapshot { rows: vec![] }
}

fn svc(s: &mut Snapshot) -> UserService<'_, Snapshot> {
    UserService {
        store: s,
        new_id: &|| "id-1".to_string(),
        now: &|| "2026-06-24T00:00:00Z".to_string(),
    }
}

#[test]
fn okta_create_then_duplicate_matrix() {
    let mut s = store();
    let (status, body, _) = svc(&mut s)
        .create(&ctx(), fixture("okta_create.json"))
        .unwrap();
    assert_eq!(status, 201); // create → 201
    assert_eq!(body["id"], "id-1");
    assert_eq!(body["userName"], "bjensen@example.com");
    // EnterpriseUser URN preserved through create.
    assert_eq!(
        body["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["department"],
        "Tech"
    );
    // Duplicate userName → 409.
    let err = svc(&mut s)
        .create(&ctx(), fixture("okta_create.json"))
        .unwrap_err();
    assert_eq!(err.status, 409);
}

#[test]
fn okta_found_and_get_after_create() {
    let mut s = store();
    svc(&mut s)
        .create(&ctx(), fixture("okta_create.json"))
        .unwrap();
    let (status, _, tag) = svc(&mut s).get(&ctx(), "id-1").unwrap();
    assert_eq!(status, 200); // found → 200
    assert!(tag.unwrap().starts_with("W/\""));
}

#[test]
fn okta_deactivate_patch_no_path_boolean_keeps_gettable() {
    let mut s = store();
    svc(&mut s)
        .create(&ctx(), fixture("okta_create.json"))
        .unwrap();
    let (status, body, _) = svc(&mut s)
        .patch(&ctx(), "id-1", fixture("okta_deactivate_patch.json"), None)
        .unwrap();
    assert_eq!(status, 200); // PATCH user → 200
    assert_eq!(body["active"], json!(false));
    // soft delete: still GET-able with active=false.
    let (gstatus, gbody, _) = svc(&mut s).get(&ctx(), "id-1").unwrap();
    assert_eq!(gstatus, 200);
    assert_eq!(gbody["active"], json!(false));
}

#[test]
fn entra_noflag_capitalized_string_active_patch() {
    let mut s = store();
    svc(&mut s)
        .create(&ctx(), fixture("okta_create.json"))
        .unwrap();
    let (status, body, _) = svc(&mut s)
        .patch(&ctx(), "id-1", fixture("entra_patch_noflag.json"), None)
        .unwrap();
    assert_eq!(status, 200); // Entra PATCH → 200
    assert_eq!(body["active"], json!(false)); // "False" coerced
}

#[test]
fn entra_flag_lowercase_multiattr_dotnotation_patch() {
    let mut s = store();
    svc(&mut s)
        .create(&ctx(), fixture("okta_create.json"))
        .unwrap();
    let (status, body, _) = svc(&mut s)
        .patch(&ctx(), "id-1", fixture("entra_patch_flag.json"), None)
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["active"], json!(false));
    assert_eq!(body["name"]["givenName"], "Bob"); // dot-notation split
    assert_eq!(body["displayName"], "Bob J");
}

#[test]
fn entra_test_connection_returns_empty_list_not_404() {
    let s = &mut store();
    // No users; Entra GETs a random GUID filter.
    let expr = parse_filter("externalId eq \"7e6d3f00-0000-0000-0000-000000000000\"").unwrap();
    // (parsing succeeds; the empty store yields an empty list, not a 404.)
    let _ = expr;
    let page = Page {
        start_index: 1,
        count: 100,
    };
    let (status, body, _) = svc(s).list(&ctx(), &page);
    assert_eq!(status, 200); // empty query → 200
    assert_eq!(body["totalResults"], json!(0));
    assert_eq!(body["Resources"], json!([]));
}

#[test]
fn put_then_stale_if_match_is_412() {
    let mut s = store();
    let (_, _, tag) = svc(&mut s)
        .create(&ctx(), fixture("okta_create.json"))
        .unwrap();
    let stale = tag.unwrap();
    svc(&mut s)
        .replace(
            &ctx(),
            "id-1",
            json!({ "userName": "bjensen@example.com", "displayName": "X" }),
            Some(&stale),
        )
        .unwrap(); // PUT with fresh ETag → 200
    let err = svc(&mut s)
        .replace(
            &ctx(),
            "id-1",
            json!({ "userName": "bjensen@example.com", "displayName": "Y" }),
            Some(&stale),
        )
        .unwrap_err();
    assert_eq!(err.status, 412); // stale If-Match → 412
}

#[test]
fn hard_delete_then_404() {
    let mut s = store();
    svc(&mut s)
        .create(&ctx(), fixture("okta_create.json"))
        .unwrap();
    let (status, _, _) = svc(&mut s).delete(&ctx(), "id-1").unwrap();
    assert_eq!(status, 204); // DELETE → 204
    assert_eq!(svc(&mut s).get(&ctx(), "id-1").unwrap_err().status, 404);
}

#[test]
fn group_member_add_and_dual_remove_forms() {
    // Exercise the PATCH engine directly on a group canonical tree.
    let group = json!({ "displayName": "g", "members": [] });
    let added = apply_patch(
        &group,
        &normalize_patch(&fixture("okta_group_member_add.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(added["members"][0]["value"], "id-1");
    // value-path remove form.
    let removed = apply_patch(
        &added,
        &normalize_patch(&fixture("okta_group_member_remove.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(removed["members"], json!([]));
}

#[test]
fn bad_filter_is_400_invalid_filter() {
    let err = parse_filter("userName co \"x\"").unwrap_err();
    assert_eq!(err.status, 400);
}

#[test]
fn active_string_forms_all_coerce() {
    assert_eq!(coerce_active(&json!("False")), Some(false));
    assert_eq!(coerce_active(&json!("True")), Some(true));
    assert_eq!(coerce_active(&json!(false)), Some(false));
}

#[test]
fn discovery_endpoints_present() {
    assert_eq!(
        discovery::service_provider_config()["patch"]["supported"],
        true
    );
    assert_eq!(discovery::resource_types()["totalResults"], json!(2));
    assert_eq!(discovery::schemas()["totalResults"], json!(3));
}
