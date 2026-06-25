# Tessera Data Model Reference

This document describes every persistent and in-flight data shape in the Tessera
identity engine: SCIM 2.0 Users and Groups (D1), session state (Durable Object),
telemetry events (Queue + DO ring buffer), audit records, RBAC-A policy data, and
JWT/JWKS claim sets.

---

## 1. SCIM 2.0 User

### 1.1 Schema URNs

| Constant | URN |
|---|---|
| Core User | `urn:ietf:params:scim:schemas:core:2.0:User` |
| Enterprise extension | `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User` |
| Group | `urn:ietf:params:scim:schemas:core:2.0:Group` |
| List response | `urn:ietf:params:scim:api:messages:2.0:ListResponse` |
| Patch op | `urn:ietf:params:scim:api:messages:2.0:PatchOp` |

### 1.2 User resource (full)

```json
{
  "schemas": [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
  ],
  "id": "2819c223-7f76-453a-919d-413861904646",
  "externalId": "okta-00u1abcdefghIJKLM012",
  "userName": "alice@acme.example",
  "name": {
    "formatted": "Alice Liddell",
    "familyName": "Liddell",
    "givenName": "Alice"
  },
  "displayName": "Alice Liddell",
  "emails": [
    {"value": "alice@acme.example", "type": "work", "primary": true}
  ],
  "active": true,
  "groups": [
    {
      "value": "e9e30dba-f08f-4109-8486-d5c6a331660a",
      "$ref": "https://idp.lifecycle.example/scim/v2/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a",
      "display": "Engineering"
    }
  ],
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
    "employeeNumber": "EMP-42",
    "organization": "Acme Corp",
    "department": "Engineering",
    "costCenter": "CC-100",
    "division": "Platform",
    "manager": {
      "value": "0db508eb-91e2-46e4-809c-30dcbda0c685",
      "displayName": "Bob Manager"
    }
  },
  "meta": {
    "resourceType": "User",
    "created": "2026-06-24T10:00:00Z",
    "lastModified": "2026-06-24T11:30:00Z",
    "location": "https://idp.lifecycle.example/scim/v2/Users/2819c223-7f76-453a-919d-413861904646",
    "version": "W/\"3\""
  }
}
```

**Field notes:**
- `active` defaults to `true` when omitted on create (RFC 7643 §4.1.1)
- `extensions` (any unrecognized URN key) are stored in a `BTreeMap<String, Value>` and round-trip losslessly
- The `version` ETag value matches the D1 `version` integer column, formatted as `W/"<n>"`
- Okta sends `active` as a string `"true"`/`"false"` in PATCH bodies; the engine coerces it to boolean

### 1.3 D1 table: `scim_users`

```sql
CREATE TABLE scim_users (
  tenant       TEXT NOT NULL,
  id           TEXT NOT NULL,
  user_name    TEXT NOT NULL,
  external_id  TEXT,
  active       INTEGER NOT NULL DEFAULT 1,
  display_name TEXT,
  body         TEXT NOT NULL,      -- canonical JSON, full ScimUser
  version      INTEGER NOT NULL DEFAULT 1,
  created      TEXT NOT NULL,      -- ISO 8601
  last_modified TEXT NOT NULL,     -- ISO 8601
  PRIMARY KEY (tenant, id)
);

CREATE UNIQUE INDEX scim_users_tenant_username ON scim_users (tenant, user_name);
CREATE INDEX scim_users_tenant_extid          ON scim_users (tenant, external_id);
```

The `body` column stores the complete `ScimUser` JSON. Indexed columns
(`user_name`, `external_id`, `active`, `display_name`) are projected out for
filtered queries and kept consistent with `body` on every write.

### 1.4 Group resource

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "id": "e9e30dba-f08f-4109-8486-d5c6a331660a",
  "externalId": "okta-grp-00g1abc",
  "displayName": "Engineering",
  "members": [
    {
      "value": "2819c223-7f76-453a-919d-413861904646",
      "$ref": "https://idp.lifecycle.example/scim/v2/Users/2819c223-7f76-453a-919d-413861904646",
      "display": "Alice Liddell"
    }
  ],
  "meta": {
    "resourceType": "Group",
    "created": "2026-06-24T09:00:00Z",
    "lastModified": "2026-06-24T09:00:00Z",
    "location": "https://idp.lifecycle.example/scim/v2/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a",
    "version": "W/\"1\""
  }
}
```

### 1.5 D1 table: `scim_groups`

```sql
CREATE TABLE scim_groups (
  tenant        TEXT NOT NULL,
  id            TEXT NOT NULL,
  display_name  TEXT NOT NULL,
  external_id   TEXT,
  body          TEXT NOT NULL,      -- canonical JSON, full ScimGroup
  version       INTEGER NOT NULL DEFAULT 1,
  created       TEXT NOT NULL,
  last_modified TEXT NOT NULL,
  PRIMARY KEY (tenant, id)
);

CREATE UNIQUE INDEX scim_groups_tenant_displayname ON scim_groups (tenant, display_name);
```

---

## 2. Identity lifecycle state (JML)

The identity lifecycle moves through Joiner / Mover / Leaver (JML) states,
reflected in the user's `active` flag and the `TelemetryEvent.phase` field.

| State | `active` | Description |
|---|---|---|
| `hired` | `true` | Account provisioned; access flows active |
| `moved` | `true` | Role/tenant change in progress |
| `departed` | `false` | Account soft-deleted (`PATCH active=false`) |
| `purged` | — | Hard-deleted from D1 (`DELETE`) |

State transitions are driven by the upstream IdP (Okta SCIM push or Entra
provisioning) and are observable via the telemetry SSE stream (`phase:
lifecycle`).

---

## 3. Session state (Durable Object)

Sessions are stored inside the `SessionStore` Durable Object (D1-backed SQLite
within the DO). The DO instance is globally named `"global"` (`SESSIONS` binding).

### 3.1 Session record

```json
{
  "token": "b64url-256bit-csprng-opaque-value",
  "sub": "rp:a1b2c3d4",
  "created": 1750000000,
  "expires": 1750003600
}
```

| Field | Type | Description |
|---|---|---|
| `token` | string | 256-bit CSPRNG opaque token (base64url, 43 chars) |
| `sub` | string | Subject — `"rp:<first-8-of-state>"` for RP-initiated sessions |
| `created` | u64 | Epoch seconds, set at creation |
| `expires` | u64 | Epoch seconds (`created + 3600`) |

### 3.2 Session status

The DO resolves a token to one of four statuses:

| Status | Meaning |
|---|---|
| `active` | Token known, `now < expires`, not revoked |
| `expired` | Token known, `now >= expires` |
| `revoked` | Token explicitly revoked via `POST /logout` |
| `unknown` | Token not found in the DO |

Revoked beats expired: a token revoked before its natural expiry is always
`revoked`.

### 3.3 Session cookie

```
Set-Cookie: __Host-sid=<token>; Max-Age=3600; Path=/; HttpOnly; Secure; SameSite=Strict
```

The `__Host-` prefix enforces `Secure`, `Path=/`, and no `Domain` attribute
(browser spec §4.1.3). The cookie is cleared on logout with `Max-Age=0`.

---

## 4. TelemetryEvent

Emitted by the edge engine to the `TELEMETRY_QUEUE` Cloudflare Queue. Aggregated
by the `TELEMETRY_DO` Durable Object ring buffer and streamed to browsers via SSE.

```json
{
  "v": 1,
  "id": "42",
  "ts": 1750000001000,
  "node": "edge",
  "edge": "idp-edge",
  "phase": "authn",
  "label": "OIDC code exchange"
}
```

| Field | Type | Constraints | Description |
|---|---|---|---|
| `v` | integer | always `1` | Schema version |
| `id` | string | monotonic | Used as SSE `id:` frame and `Last-Event-ID` for replay |
| `ts` | integer | epoch ms | Emission timestamp |
| `node` | string | enum | Graph node: `idp`, `edge`, `opa`, `control`, `aws`, `azure`, `gcp` |
| `edge` | string \| null | enum \| null | Graph edge: `idp-edge`, `edge-opa`, `edge-control`, `edge-aws`, `edge-azure`, `edge-gcp`; `null` for node-local events |
| `phase` | string | enum | `request`, `authn`, `authz`, `lifecycle`, `federation`, `complete`, `error` |
| `label` | string | non-empty | Human-readable event description |

**SSE wire frame:**

```
id: 42
data: {"v":1,"id":"42","ts":1750000001000,"node":"edge","edge":"idp-edge","phase":"authn","label":"OIDC code exchange"}

```

---

## 5. Audit record (hash chain)

Decision events are logged in an OPA-shaped audit record with a tamper-evident
hash chain. Each record is linked to the previous via `prev_hash`.

```json
{
  "decision_id": "01J3ZK7VQ2X8E4N0MHPW6GBTF",
  "seq": 1001,
  "path": "data.authz.allow",
  "input": {
    "subject": {"id": "alice", "roles": ["reader"], "tenant": "acme"},
    "resource": {"type": "users", "tenant": "acme"},
    "action": "read",
    "environment": {}
  },
  "result": true,
  "requested_by": "control-plane",
  "timestamp": "2026-06-24T10:00:01.000Z",
  "record_hash": "sha256:<hex-of-this-record-canonical-json>",
  "prev_hash": "sha256:<hex-of-previous-record>"
}
```

| Field | Type | Description |
|---|---|---|
| `decision_id` | string | ULID — unique, sortable |
| `seq` | integer | Monotonic sequence number |
| `path` | string | Always `"data.authz.allow"` (= `ALLOW_QUERY` constant) |
| `input` | object | Masked copy of the `AuthzInput` (see §5.1) |
| `result` | boolean | The `allow` value |
| `requested_by` | string | Caller identifier |
| `timestamp` | string | ISO 8601 |
| `record_hash` | string | SHA-256 of canonical JSON of this record (before `record_hash` is set) |
| `prev_hash` | string | `record_hash` of the preceding record (`"genesis"` for seq=1) |

### 5.1 Input masking

The following fields are redacted from `input.subject` before the record is
written: `password`, `token`, `secret`, `authorization`, `credential`.
The `subject.id` is truncated to 8 characters.

---

## 6. RBAC-A policy data shapes

The Rego policy bundle (`policy/authz/`) is loaded from signed JSON data files.
Below are the shapes of each data document.

### 6.1 RBAC data (`rbac_data.json`)

```json
{
  "roles": {
    "admin": ["editor"],
    "editor": ["reader"],
    "reader": []
  },
  "role_permissions": [
    {"role": "reader", "resource": "users",   "action": "read"},
    {"role": "editor", "resource": "users",   "action": "write"},
    {"role": "admin",  "resource": "users",   "action": "delete"},
    {"role": "admin",  "resource": "groups",  "action": "delete"}
  ],
  "user_roles": [
    {"subject": "alice", "role": "reader", "tenant": "acme"},
    {"subject": "bob",   "role": "admin",  "tenant": "acme"}
  ]
}
```

`roles` is an adjacency map representing the role hierarchy. `graph.reachable`
over this map yields the effective role set for a subject — `admin` inherits all
`editor` and `reader` permissions.

### 6.2 ABAC data (`abac_data.json`)

```json
{
  "mfa_required_resources": ["users", "groups", "secrets"],
  "device_trust_ranks": {
    "managed": 2,
    "unmanaged": 1,
    "unknown": 0
  },
  "required_device_rank": 1,
  "maintenance_actions": ["delete", "purge"]
}
```

ABAC rules fire as violations; `abac_ok` is true only when
`count(abac_violations) == 0`. Violations:
- `tenant_mismatch`: `input.subject.tenant != input.resource.tenant` (BOLA guard)
- `mfa_required`: resource in `mfa_required_resources` and `input.subject.mfa != true`
- `device_posture`: `device_trust_ranks[input.subject.device_trust] < required_device_rank`
- `outside_maintenance_window`: action in `maintenance_actions` and `input.environment.maintenance_window == false`

### 6.3 SoD data (`sod_data.json`)

```json
{
  "toxic_pairs": [
    ["requester", "approver"],
    ["auditor",   "admin"]
  ],
  "self_approval_actions": ["approve", "certify"]
}
```

SoD rules:
- `sod_conflict` (preventive): subject holds both roles in a `toxic_pair`
- `self_approval` (preventive): action is a self-approval action and `input.subject.id == input.resource.owner`

### 6.4 Input categories (NIST ABAC)

The `AuthzInput` maps to four NIST ABAC categories:

| Category | Field path | Example |
|---|---|---|
| Subject | `input.subject` | `{"id":"alice","roles":["reader"],"tenant":"acme","mfa":true}` |
| Resource | `input.resource` | `{"type":"users","tenant":"acme"}` |
| Action | `input.action` | `"read"` |
| Environment | `input.environment` | `{"maintenance_window":false}` |

---

## 7. Signed policy bundle

The policy bundle is a JSON envelope carrying Rego sources and data. It is
signed with Ed25519 by the `tools/sign_bundle.py` signer and verified by
`authz/bundle.rs` on every `/decision` call.

```json
{
  "revision": "2026-06-24.1",
  "policies": {
    "main.rego":  "<rego source>",
    "rbac.rego":  "<rego source>",
    "abac.rego":  "<rego source>",
    "sod.rego":   "<rego source>"
  },
  "data": {
    "authz": {
      "rbac_data": { "...": "..." },
      "abac_data": { "...": "..." },
      "sod_data":  { "...": "..." }
    }
  },
  "hashes": {
    "main.rego": "sha256:<hex>",
    "rbac.rego": "sha256:<hex>",
    "abac.rego": "sha256:<hex>",
    "sod.rego":  "sha256:<hex>"
  },
  "data_hash": "sha256:<hex-of-canonical-data-json>"
}
```

**Verification steps (Rust `bundle.rs`):**
1. Deserialize the manifest JSON.
2. Recompute SHA-256 of each policy source and the canonical `data` JSON
   (`json.dumps(sort_keys=True, separators=(",",":"))` equivalent).
3. Compare computed hashes against `hashes` and `data_hash`.
4. Compute `sha256(canonical({revision, hashes, data_hash}))`.
5. Verify the detached Ed25519 signature in `AUTHZ_BUNDLE_SIG` over that digest
   using the public key in `AUTHZ_BUNDLE_PUBKEY`.
6. Any mismatch causes a fail-closed deny (`"policy unavailable: …"`).

---

## 8. JWT / JWKS claim sets

### 8.1 Internal EdDSA token

Signed with `kid: int-2026-06` (Ed25519, 32-byte seed from `INTERNAL_ED25519_SEED`).
Used for internal service-to-service calls within the Tessera trust boundary.

**JOSE header**
```json
{
  "alg": "EdDSA",
  "kid": "int-2026-06",
  "typ": "JWT"
}
```

**Payload**
```json
{
  "iss": "https://idp.lifecycle.example",
  "sub": "service:control-plane",
  "aud": "https://idp.lifecycle.example",
  "iat": 1750000000,
  "nbf": 1750000000,
  "exp": 1750003600
}
```

**Public JWK (no `d` — private key never exported)**
```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "kid": "int-2026-06",
  "use": "sig",
  "x": "<base64url-32-byte-public-key>"
}
```

### 8.2 Cloud RS256 federation token

Signed with `kid: cloud-2026-06` (RSA, `CLOUD_RSA_PKCS8_DER_B64`).
Presented to cloud STS endpoints (AWS `AssumeRoleWithWebIdentity`, Azure
`ExchangeToken`, GCP `GenerateAccessToken`) to obtain cloud-native credentials.

**JOSE header**
```json
{
  "alg": "RS256",
  "kid": "cloud-2026-06",
  "typ": "JWT"
}
```

**Payload — AWS example**
```json
{
  "iss": "https://idp.lifecycle.example",
  "sub": "arn:aws:iam::123456789012:role/lifecycle-worker",
  "aud": "sts.amazonaws.com",
  "iat": 1750000000,
  "exp": 1750000900
}
```

**Audience by cloud**

| Cloud | `aud` |
|---|---|
| AWS | `sts.amazonaws.com` |
| Azure | `api://AzureADTokenExchange` |
| GCP | `https://iam.googleapis.com/` |

**Public JWK**
```json
{
  "kty": "RSA",
  "kid": "cloud-2026-06",
  "use": "sig",
  "alg": "RS256",
  "n": "<modulus-base64url>",
  "e": "AQAB"
}
```

### 8.3 JWT verification invariants

The `jwt::verify_jwt` pipeline enforces (RFC 8725 + alg-confusion defence):
- Header `alg` must match the expected algorithm — `alg: none` is always rejected
- No algorithm confusion between EdDSA and RS256 keys
- `typ` must equal `"JWT"`
- `iss` and `aud` must match expected values
- `exp` is validated against a caller-supplied `now` (WASM clock-safe, no
  `SystemTime`)
- `nbf` is checked when present

---

## 9. Conformance test vectors

The policy conformance test suite (`policy/conformance/vectors.json`, schema
version `2026-06-24.1`) carries 10 named vectors. Each vector is:

```json
{
  "name": "reader-read-allow",
  "query": "data.authz.allow",
  "input": { "subject": {...}, "resource": {...}, "action": "read", "environment": {} },
  "expected": true
}
```

Vectors cover: reader-read (allow), reader-delete (deny — envelope), admin-delete
with full ABAC (allow), admin-delete without MFA (deny), unmanaged device (deny),
cross-tenant BOLA (deny), toxic role pair (deny), self-approval (deny), clean
approver (allow), empty input (deny). These vectors are replayed by the embedded
Regorus engine in Rust CI (`conformance.rs`) and by `opa test` in CI.

---

## 10. Cloudflare binding summary

| Binding | Type | Data stored |
|---|---|---|
| `SESSIONS` (DO `SessionStore`) | Durable Object (SQLite) | Session records: `token`, `sub`, `created`, `expires`, `status` |
| `DB` (D1 `lifecycle`) | D1 (SQLite) | `scim_users`, `scim_groups` tables |
| `JWKS_CACHE` | KV namespace | `rsa_jwk` (RSA public JWK), `rp:<state>` (OIDC stash with nonce + verifier, TTL 300 s) |
| `TELEMETRY_QUEUE` | Queue (producer) | `TelemetryEvent` messages (JSON, schema v1) |
| `TELEMETRY_DO` | Durable Object | In-memory `EventRing` ring buffer; per-subscriber SSE fan-out |
