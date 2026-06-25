# ADR-0012: Audit Log — Append-Only, Hash-Chained, Redact-Before-Write on R2 (WORM + App-Level Integrity)

**Status:** Accepted

---

## Context

Tessera is an identity engine handling authentication, authorization, provisioning, and offboarding decisions. Audit logging for these operations is required by NIST SP 800-53 r5 (AU family), OWASP ASVS V16, and standard compliance frameworks (SOC 2 CC6.1–6.3, ISO 27001:2022 §5.15–5.18, SOX ITGC for access-review evidence). The audit log must be:

- **Complete:** every authorization decision, session event, SCIM operation, JML transition, and access review decision is recorded (NIST AU-2 / AU-3).
- **Tamper-evident:** an adversary who gains write access to the log store should not be able to silently modify or delete past records without that modification being detectable (NIST AU-10).
- **Retention-compliant:** access review records are SOX evidence — minimum 7-year retention (NIST AU-11).
- **Privacy-safe:** credentials, tokens, PII beyond what is necessary for the audit event must never appear in logs (OWASP Logging Cheat Sheet; GDPR / privacy minimization).

**Storage: Cloudflare R2**

Research brief 05 (`docs/superpowers/research/05-cloudflare-rust-go-stack.md`) confirmed that R2 has **Bucket Locks** providing WORM-style retention — but critically, this is **not** equivalent to AWS S3 Object Lock in Compliance mode (which makes objects legally immutable to the account owner). R2 Bucket Locks can be overridden by account-level actions. Therefore, application-level integrity guarantees (hash chaining) are required as the primary tamper-evidence mechanism; R2 Bucket Locks are a defense-in-depth backstop, not the sole control.

Research brief 02 (`docs/superpowers/research/02-scim-lifecycle-rbac-zerotrust-audit.md`, §6) establishes the Tessera audit scheme:

> "R2 Bucket Locks (WORM-style, not Compliance mode) + hash chaining + signed Merkle checkpoints (Ed25519). Per-record `seq`+`record_hash`+`prev_hash`, chain head in per-tenant DO, periodic signed checkpoint, published verifier."

**Hash chaining:**

Each audit record carries:
- `seq`: monotonically increasing sequence number per tenant.
- `record_hash`: SHA-256 of the record content (after redaction, before any encoding).
- `prev_hash`: `record_hash` of the immediately preceding record in the chain.

The first record in a chain sets `prev_hash = SHA-256("genesis-<tenant_id>")`. Any tampering with a record (content modification or deletion) breaks the chain at that point: the `record_hash` will no longer match the hash of the actual content, and the next record's `prev_hash` will no longer match the previous record's `record_hash`.

**Signed Merkle checkpoints:**

Periodically (e.g., every 1,000 records or every hour), the Go control plane computes a Merkle root over the current chain segment and publishes a checkpoint: `{tenant_id, seq_range, merkle_root, timestamp, signature}` signed with the Ed25519 identity key. Checkpoints are stored separately (also in R2) and can be independently verified. This provides:
- Efficient batch verification without re-reading the entire chain.
- A tamper-evidence anchor that is harder to retroactively forge.

**Redact-before-write:**

Log records must never contain: authentication credentials (passwords, tokens, bearer values), private key material, or PII beyond `{user_id, tenant_id}`. The redaction must happen **before** the record is hashed — if a token appears in the pre-hash content, it is in the hash preimage and effectively committed to the chain. The Rust host code enforces redaction by:
- Never including `Authorization` header values in log input.
- Never including full token values — log the `jti` (JWT ID) or a truncated fingerprint (first 8 chars of SHA-256 of the token).
- Never logging SCIM User `password` or `x509Certificates` attributes.
- Logging `event_time` (the time the event occurred) and `ingest_time` (the time the record was written) separately — they differ in async/queue paths.

**Mutable vs immutable stores:**

Research brief 02 (§6) clarifies the role of each Cloudflare primitive:
- **D1 / Durable Objects:** mutable, queryable — used for live operational state (current session, current role assignments, access review queue). NOT the system of record for audit.
- **R2:** append-only record of record. Each audit event is a separate R2 object (`/audit/{tenant_id}/{year}/{month}/{day}/{seq}-{uuid}.json`). Objects are never updated; old objects are only deleted when the retention period expires.

**Decision logging for Regorus:**

OWASP ASVS V16 (L3) requires logging all authorization decisions. Regorus has no built-in decision-log plugin (ADR-0003). The Rust host code emits a decision log entry for every Regorus evaluation: `{decision_id (UUID), input (redacted), result (allow/deny + reasons), policy_revision, timestamp}`. These flow to the audit Queue → aggregator → R2.

**Six required NIST AU-3 elements per record:**
Who (`sub`, `tenant_id`), What (event type + resource), When (`event_time`, `ingest_time`), Where (endpoint, client IP), Outcome (`allow`/`deny`/`success`/`failure`), Correlation (`decision_id`, `session_id`, `request_id`).

---

## Decision

Tessera's audit log is **append-only, hash-chained, and written to R2** with R2 Bucket Locks (WORM-style) as backstop and application-level hash chaining as the primary tamper-evidence control. All records are **redacted before hashing and writing**.

**Record schema (per R2 object):**
```json
{
  "seq": 12345,
  "tenant_id": "t_abc",
  "event_time": "2026-06-24T10:00:00.000Z",
  "ingest_time": "2026-06-24T10:00:00.012Z",
  "event_type": "authz.decision",
  "who": { "sub": "user:alice", "session_id": "sess_xyz", "client_ip": "1.2.3.4" },
  "what": { "resource_type": "Group", "resource_id": "grp_001", "action": "write" },
  "outcome": "deny",
  "details": { "decision_id": "uuid-v4", "policy_revision": "sha256:abc...", "reasons": ["role_insufficient"] },
  "record_hash": "sha256:...",
  "prev_hash": "sha256:..."
}
```

**R2 object path:** `audit/{tenant_id}/{YYYY}/{MM}/{DD}/{seq:010d}-{uuid}.json`

**Chain head tracking:** per-tenant Durable Object stores `{last_seq, last_hash}` — the writer reads this atomically before appending each record. The DO's single-writer strong consistency prevents concurrent writes from forking the chain.

**Checkpoint schedule:** Go control plane Cron job runs every hour; builds Merkle checkpoint over the last segment; signs with Ed25519 tenant key; stores checkpoint object to `audit/{tenant_id}/checkpoints/{seq_end}.json`.

**Redaction enforcement (Rust host):**
- Input to audit record: scrub all header values, token strings, password fields.
- Log token identity via `jti` or `SHA-256(token)[0:8]` — never the full value.
- Separate `event_time` from `ingest_time`; always UTC RFC 3339 with millisecond precision.
- Log injection prevention: validate all string fields before serialization; do not interpolate strings via format macros with user-controlled input.

**Retention policy:**
- Default: 7 years (SOX evidence floor for access-review records).
- R2 Bucket Lock retention duration set at bucket creation.
- Cloudflare R2 Lifecycle rules delete objects after retention period expires.

**Verification tooling:**
- A published verifier (Go binary or simple web page) allows any stakeholder to verify chain integrity given a tenant's R2 objects and the checkpoint signatures — independently, without trusting the Tessera control plane.

---

## Consequences

**Positive:**
- Tamper-evident at the application layer: any modification or deletion of a record breaks the hash chain at that point, detectable by the verifier.
- Signed Merkle checkpoints provide efficient batch verification and a time-stamped integrity anchor.
- R2 WORM provides a storage-layer backstop against casual deletion.
- Redact-before-write ensures credential material is never committed to the audit log hash chain.
- Append-only R2 objects are naturally queryable by time range via the path prefix convention.
- Per-tenant DO chain-head tracking ensures strict sequence ordering with no forks.

**Negative / Tradeoffs:**
- R2 Bucket Locks are not equivalent to S3 Compliance mode — a Cloudflare account-level action could override them. The hash chain and signed checkpoints are the primary controls; R2 Bucket Locks are defense-in-depth only.
- Chain-head DO introduces a per-tenant serialization bottleneck: every audit record write requires a DO round-trip. For high-throughput tenants, batch appending (queue → aggregator → single-batch R2 write) is required.
- Merkle checkpoint computation (Go control plane Cron) must handle gaps if the control plane is unavailable — gaps in checkpoint coverage reduce the benefit of Merkle proofs for that interval.
- 7-year R2 retention creates long-term storage cost. At Cloudflare R2 free-tier pricing (10 GB free), this is negligible for a portfolio project; for production it requires budgeting.
- Verification requires reading potentially large numbers of R2 objects for full chain verification — spot verification via checkpoints is practical, full-chain verification is only needed for incident investigation.

---

## Alternatives Considered

| Option | Reason Rejected |
|---|---|
| Mutable D1 or Durable Object storage for audit log | D1 and DO are mutable — records can be updated or deleted. Fail NIST AU-10 (non-repudiation/integrity). |
| R2 WORM only, no hash chain | R2 Bucket Locks are WORM-style but not S3 Compliance mode — account-level overrides possible. Hash chain provides stronger tamper evidence independent of the storage provider. |
| External SIEM (Splunk, Datadog) | Adds external SaaS dependency; for the Tessera demo scope, R2 + Queues is sufficient and fully within Cloudflare ecosystem. An external SIEM can be wired as a secondary sink. |
| Simple flat log without sequence numbers | No ordering guarantee, no chain integrity. Cannot detect missing records. |
| JWT-signed individual records (no chain) | Each record can be verified in isolation but missing records are undetectable — an adversary can silently delete individual entries. |

---

## References

- Research brief 02: `docs/superpowers/research/02-scim-lifecycle-rbac-zerotrust-audit.md` (§6 Audit logging)
- Research brief 05: `docs/superpowers/research/05-cloudflare-rust-go-stack.md` (§ R2 / Durable Objects / KV)
- Design spec §3 Cloudflare resource map, §4 Layer 1, §5 Security model: `docs/superpowers/specs/2026-06-24-lifecycle-identity-engine-design.md`
- NIST SP 800-53 r5, AU family (AU-2, AU-3, AU-9, AU-10, AU-11): https://doi.org/10.6028/NIST.SP.800-53r5
- NIST SP 800-92 (Guide to Computer Security Log Management): https://doi.org/10.6028/NIST.SP.800-92
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP ASVS v5.0, V16 (Logging and Error Handling): https://owasp.org/ASVS
- Cloudflare R2 Bucket Locks: https://developers.cloudflare.com/r2/buckets/object-lock/
- CISA M-21-31 (Improving Investigative and Remediation Capabilities): https://www.whitehouse.gov/wp-content/uploads/2021/08/M-21-31-Improving-the-Federal-Governments-Investigative-and-Remediation-Capabilities-Related-to-Cybersecurity-Incidents.pdf
