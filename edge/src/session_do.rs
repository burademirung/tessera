//! Single-writer, strongly consistent session store. Instant revocation and
//! "log out everywhere" via SQLite-backed Durable Object storage. WASM-only.

use crate::session::{evaluate, SessionRecord, SessionStatus};
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
