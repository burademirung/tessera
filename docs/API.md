# Tessera Edge API Reference

Tessera is a bespoke identity engine deployed as a Rust/WASM Cloudflare Worker.
This document covers every HTTP endpoint exposed by the edge worker, including the
SCIM 2.0 service provider surface, the OIDC RP flow, the federation token mint,
the authorization PEP, and the live-telemetry SSE stream.

**Base URL:** `https://idp.lifecycle.example`

---

## Authentication model

| Endpoint group | Secret that gates it | Mechanism |
|---|---|---|
| `POST /introspect` | `INTROSPECT_BEARER_TOKEN` | `Authorization: Bearer <secret>` (constant-time) |
| `POST /federate` | `FEDERATION_API_TOKEN` | `Authorization: Bearer <secret>` (constant-time) |
| `POST /decision` | `AUTHZ_BUNDLE` + `AUTHZ_BUNDLE_SIG` + `AUTHZ_BUNDLE_PUBKEY` | Ed25519-signed policy bundle verified at startup |
| `/scim/v2/**` | `SCIM_BEARER_TOKEN` + `SCIM_TENANT_ID` | `Authorization: Bearer <secret>` (constant-time) |
| `/authorize`, `/callback`, `/logout` | Session cookie `__Host-sid` | 256-bit CSPRNG opaque token in `SessionStore` DO |
| `/.well-known/openid-configuration`, `/jwks` | None | Public, cached 300 s |

**Fail-closed invariant.** Every secret-gated endpoint returns `401` or a deny
response if the corresponding Cloudflare Secret binding is absent or the
presented credential does not match. No path leaks a partial or default-open
response when secrets are unset.

---

## 1. OpenID Connect Discovery

### `GET /.well-known/openid-configuration`

Returns the OIDC provider metadata document (RFC 8414). All endpoint URLs
derive from the issuer string `https://idp.lifecycle.example`.

**Auth required:** No  
**Cache-Control:** `public, max-age=300`

**Response `200 OK`**

```json
{
  "issuer": "https://idp.lifecycle.example",
  "jwks_uri": "https://idp.lifecycle.example/jwks",
  "authorization_endpoint": "https://idp.lifecycle.example/authorize",
  "token_endpoint": "https://idp.lifecycle.example/token",
  "introspection_endpoint": "https://idp.lifecycle.example/introspect",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["EdDSA", "RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["openid", "profile", "email"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "nbf"]
}
```

> `S256` is the only advertised PKCE method. `plain` is never listed.

**curl example**

```bash
curl -s https://idp.lifecycle.example/.well-known/openid-configuration | jq .
```

---

## 2. JSON Web Key Set

### `GET /jwks`

Returns the public JWK Set for token verification. The response always contains
at least the internal EdDSA key (`kid: int-2026-06`). When the RSA cloud key has
been cached in the `JWKS_CACHE` KV namespace, its public JWK is appended.
Private key material (`d`, `p`, `q`, `dp`, `dq`, `qi`) is never included.

**Auth required:** No  
**Cache-Control:** `public, max-age=300`

**Response `200 OK`**

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "int-2026-06",
      "use": "sig",
      "x": "<base64url-encoded-public-key>"
    },
    {
      "kty": "RSA",
      "kid": "cloud-2026-06",
      "use": "sig",
      "alg": "RS256",
      "n": "<modulus-base64url>",
      "e": "AQAB"
    }
  ]
}
```

The worker validates invariants before returning: all kids are distinct, every
key carries `"use":"sig"`, and no private members are present. A violation
returns `500`.

**curl example**

```bash
curl -s https://idp.lifecycle.example/jwks | jq .
```

---

## 3. OIDC Authorization (RP-initiated)

### `GET /authorize`

Initiates an OIDC authorization code flow with PKCE (S256) and state/nonce
protection. The worker generates a 256-bit CSPRNG `state`, `nonce`, and PKCE
`verifier`, stores `{nonce, verifier}` keyed by `state` in the `JWKS_CACHE` KV
namespace with a 300-second TTL, and redirects the browser to the upstream IdP
(Okta).

**Auth required:** No (browser-facing)

**Response `302 Found`**

| Header | Value |
|---|---|
| `Location` | `https://okta.example/oauth2/v1/authorize?response_type=code&client_id=lifecycle-rp&redirect_uri=https%3A%2F%2Fidp.lifecycle.example%2Fcallback&scope=openid+profile+email&state=<random>&nonce=<random>&code_challenge=<S256>&code_challenge_method=S256` |

**curl example**

```bash
# Follow the redirect chain (browser flow):
curl -v "https://idp.lifecycle.example/authorize"
# Response will be HTTP 302 to the upstream IdP authorize endpoint.
```

---

## 4. OIDC Callback (Authorization Code)

### `GET /callback`

Handles the authorization server redirect. Validates the `state` CSRF token,
performs the RFC 9207 `iss` response parameter check (mix-up defense), confirms
the `code` is present and the KV stash for the `state` exists, then creates a
session in the `SessionStore` Durable Object and sets the `__Host-sid` session
cookie.

**Auth required:** No (browser-facing; CSRF protected via `state`)

**Query parameters**

| Parameter | Required | Description |
|---|---|---|
| `code` | Yes | Authorization code from the upstream IdP |
| `state` | Yes | Must match the value stored in KV at `rp:<state>` |
| `iss` | Yes (RFC 9207) | Must equal `https://okta.example` |

**Response `200 OK`** — session established

| Header | Value |
|---|---|
| `Set-Cookie` | `__Host-sid=<token>; Max-Age=3600; Path=/; HttpOnly; Secure; SameSite=Strict` |

Body: `authenticated`

**Response `400 Bad Request`** — state mismatch, missing code, `iss` mismatch, or KV stash expired

Body: `invalid callback`

**curl example**

```bash
# The callback is driven by the browser via upstream IdP redirect:
curl -v "https://idp.lifecycle.example/callback?code=AUTH_CODE&state=STATE&iss=https%3A%2F%2Fokta.example"
```

---

## 5. Logout

### `POST /logout`

Revokes the session associated with the `__Host-sid` cookie in the
`SessionStore` Durable Object, then clears the cookie.

**Auth required:** Session cookie (`__Host-sid`)  
**Content-Type:** none required

**Response `200 OK`**

| Header | Value |
|---|---|
| `Set-Cookie` | `__Host-sid=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict` |

Body: `logged out`

If the cookie is absent or the session is already revoked, the endpoint still
returns `200` (idempotent).

**curl example**

```bash
curl -s -X POST https://idp.lifecycle.example/logout \
  -H "Cookie: __Host-sid=<session-token>"
```

---

## 6. Token Introspection

### `POST /introspect`

RFC 7662 token introspection endpoint. Returns the activity status and claims
of a session token. The caller must authenticate with a static bearer token
(`INTROSPECT_BEARER_TOKEN` Cloudflare Secret); this secret is verified
constant-time before any token lookup. Inactive, expired, or revoked tokens
return only `{"active": false}` — no `sub` or `exp` is disclosed for inactive
tokens.

**Auth required:** `Authorization: Bearer <INTROSPECT_BEARER_TOKEN>`  
**Content-Type:** `application/x-www-form-urlencoded`

**Request body**

| Field | Required | Description |
|---|---|---|
| `token` | Yes | The opaque session token to introspect |

**Response `200 OK` — active session**

```json
{
  "active": true,
  "sub": "rp:a1b2c3d4",
  "exp": 1750000000,
  "token_type": "session"
}
```

**Response `200 OK` — inactive, expired, or revoked session**

```json
{
  "active": false
}
```

**Response `401 Unauthorized`** — missing, wrong, or unconfigured bearer

**curl example**

```bash
curl -s -X POST https://idp.lifecycle.example/introspect \
  -H "Authorization: Bearer $INTROSPECT_BEARER_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=<opaque-session-token>"
```

---

## 7. Authorization Decision (PEP)

### `POST /decision`

Policy Enforcement Point. Evaluates an authorization request against the
Rego policy bundle (`data.authz.allow`) using the embedded Regorus engine.
The policy bundle is signature-verified at request time against
`AUTHZ_BUNDLE_PUBKEY` (Ed25519). If the bundle is absent, malformed, or fails
verification, the endpoint returns a Deny with reason `"policy unavailable: …"` —
it never fails open.

**Auth required:** None on the HTTP transport; the policy bundle is
authenticated via `AUTHZ_BUNDLE_SIG` + `AUTHZ_BUNDLE_PUBKEY`.  
**Content-Type:** `application/json`

**Request body — ABAC four-category input**

```json
{
  "subject": {
    "id": "user-123",
    "roles": ["reader"],
    "tenant": "acme",
    "mfa": true,
    "device_trust": "managed"
  },
  "resource": {
    "type": "users",
    "tenant": "acme"
  },
  "action": "read",
  "environment": {
    "maintenance_window": false
  }
}
```

**Response `200 OK` — allowed**

```json
{
  "allow": true,
  "reason": null
}
```

**Response `200 OK` — denied**

```json
{
  "allow": false,
  "reason": "policy denied"
}
```

**Response `200 OK` — bundle unavailable (fail-closed)**

```json
{
  "allow": false,
  "reason": "policy unavailable: no bundle"
}
```

HTTP status is always `200`; the `allow` boolean is the authoritative signal.
Callers MUST NOT grant access unless `allow === true`.

The Rego policy enforces:
- **RBAC** (`data.authz.rbac`): hierarchical role resolution via `graph.reachable`
- **ABAC** (`data.authz.abac`): tenant match (BOLA), MFA posture, device trust rank, maintenance windows
- **SoD** (`data.authz.sod`): toxic role pairs, self-approval prevention

**curl example**

```bash
curl -s -X POST https://idp.lifecycle.example/decision \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"id": "alice", "roles": ["reader"], "tenant": "acme", "mfa": true, "device_trust": "managed"},
    "resource": {"type": "users", "tenant": "acme"},
    "action": "read",
    "environment": {}
  }'
```

---

## 8. Cloud Federation Token

### `POST /federate`

Mints a short-lived RS256 JWT for workload identity federation with AWS, Azure,
or GCP. Callers must authenticate with `FEDERATION_API_TOKEN` (constant-time
Bearer check). The token is signed with the cloud RSA key (`kid: cloud-2026-06`,
`CLOUD_RSA_PKCS8_DER_B64` secret) and carries a cloud-specific audience.

**Auth required:** `Authorization: Bearer <FEDERATION_API_TOKEN>`  
**Content-Type:** `application/json`

**Request body**

```json
{
  "cloud": "aws",
  "sub": "arn:aws:iam::123456789012:role/lifecycle-worker"
}
```

| Field | Type | Constraints |
|---|---|---|
| `cloud` | string | `"aws"`, `"azure"`, or `"gcp"` (case-insensitive) |
| `sub` | string | Max 127 characters |

**Cloud → audience mapping (production)**

| Cloud | `aud` claim |
|---|---|
| `aws` | `sts.amazonaws.com` |
| `azure` | `api://AzureADTokenExchange` |
| `gcp` | `https://iam.googleapis.com/` |

**Response `200 OK`**

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImNsb3VkLTIwMjYtMDYiLCJ0eXAiOiJKV1QifQ…"
}
```

The JWT payload contains: `iss` (`https://idp.lifecycle.example`), `sub`, `aud`
(cloud-specific), `iat`, `exp` (`iat + 900`). TTL is fixed at 900 seconds.
There is no `azp` field.

**Response `400 Bad Request`** — unknown cloud or `sub` exceeds 127 chars  
**Response `401 Unauthorized`** — missing, empty, or wrong `FEDERATION_API_TOKEN`

**curl examples**

```bash
# AWS
curl -s -X POST https://idp.lifecycle.example/federate \
  -H "Authorization: Bearer $FEDERATION_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cloud":"aws","sub":"arn:aws:iam::123456789012:role/lifecycle-worker"}'

# GCP
curl -s -X POST https://idp.lifecycle.example/federate \
  -H "Authorization: Bearer $FEDERATION_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cloud":"gcp","sub":"lifecycle-sa@my-project.iam.gserviceaccount.com"}'

# Azure
curl -s -X POST https://idp.lifecycle.example/federate \
  -H "Authorization: Bearer $FEDERATION_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cloud":"azure","sub":"lifecycle-workload"}'
```

---

## 9. SCIM 2.0 Service Provider

All SCIM endpoints are mounted under `/scim/v2`. The service provider accepts
and emits `application/scim+json`. Bearer authentication is mandatory on every
request; the token is verified constant-time against `SCIM_BEARER_TOKEN`, and
the resolved `SCIM_TENANT_ID` is enforced on all resource access (cross-tenant
reads return `404`, not `403`, to avoid existence disclosure — BOLA defense).

Errors follow RFC 7644 §3.12: the `status` field is a **JSON string**, not an
integer.

**Auth header:** `Authorization: Bearer <SCIM_BEARER_TOKEN>`  
**Content-Type (requests):** `application/scim+json`  
**Content-Type (responses):** `application/scim+json`

### 9.1 Service Provider Configuration

#### `GET /scim/v2/ServiceProviderConfig`

Returns the service provider feature matrix.

**Response `200 OK`**

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
  "patch": {"supported": true},
  "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
  "filter": {"supported": true, "maxResults": 200},
  "changePassword": {"supported": false},
  "sort": {"supported": false},
  "etag": {"supported": true},
  "authenticationSchemes": [
    {
      "name": "OAuth Bearer Token",
      "description": "Authentication using an OAuth Bearer Token",
      "specUri": "https://www.rfc-editor.org/rfc/rfc6750",
      "type": "oauthbearertoken",
      "primary": true
    }
  ],
  "meta": {
    "resourceType": "ServiceProviderConfig",
    "location": "https://idp.lifecycle.example/scim/v2/ServiceProviderConfig"
  }
}
```

---

#### `GET /scim/v2/ResourceTypes`

Returns the list of resource types supported by this provider.

**Response `200 OK`** — `ListResponse` with User and Group entries.

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 2,
  "Resources": [
    {
      "id": "User",
      "name": "User",
      "endpoint": "/Users",
      "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
      "schemaExtensions": [
        {
          "schema": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
          "required": false
        }
      ],
      "meta": {"resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/User"}
    },
    {
      "id": "Group",
      "name": "Group",
      "endpoint": "/Groups",
      "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
      "meta": {"resourceType": "ResourceType", "location": "/scim/v2/ResourceTypes/Group"}
    }
  ]
}
```

---

#### `GET /scim/v2/Schemas`

Returns full attribute definitions for User, Group, and EnterpriseUser schemas.

**Response `200 OK`** — `ListResponse` wrapping schema objects per RFC 7643.

---

### 9.2 Users

#### `POST /scim/v2/Users` — Create user

**Request body**

```json
{
  "schemas": [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
  ],
  "userName": "alice@acme.example",
  "name": {
    "givenName": "Alice",
    "familyName": "Liddell",
    "formatted": "Alice Liddell"
  },
  "displayName": "Alice Liddell",
  "emails": [
    {"value": "alice@acme.example", "type": "work", "primary": true}
  ],
  "active": true,
  "externalId": "okta-00u1abc",
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
    "department": "Engineering",
    "organization": "Acme Corp",
    "manager": {
      "value": "2819c223-7f76-453a-919d-413861904646",
      "displayName": "Bob Manager"
    }
  }
}
```

**Response `201 Created`**

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "2819c223-7f76-453a-919d-413861904646",
  "userName": "alice@acme.example",
  "name": {"givenName": "Alice", "familyName": "Liddell", "formatted": "Alice Liddell"},
  "displayName": "Alice Liddell",
  "emails": [{"value": "alice@acme.example", "type": "work", "primary": true}],
  "active": true,
  "externalId": "okta-00u1abc",
  "meta": {
    "resourceType": "User",
    "created": "2026-06-24T10:00:00Z",
    "lastModified": "2026-06-24T10:00:00Z",
    "location": "https://idp.lifecycle.example/scim/v2/Users/2819c223-7f76-453a-919d-413861904646",
    "version": "W/\"1\""
  }
}
```

**Response `409 Conflict`** — `userName` already exists

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "scimType": "uniqueness",
  "detail": "userName already exists"
}
```

**curl example**

```bash
curl -s -X POST https://idp.lifecycle.example/scim/v2/Users \
  -H "Authorization: Bearer $SCIM_BEARER_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice@acme.example",
    "active": true
  }'
```

---

#### `GET /scim/v2/Users/:id` — Retrieve user

**Response `200 OK`** — full user resource (same shape as create response)  
**Response `404 Not Found`**

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "404",
  "detail": "User not found"
}
```

**curl example**

```bash
curl -s https://idp.lifecycle.example/scim/v2/Users/2819c223-7f76-453a-919d-413861904646 \
  -H "Authorization: Bearer $SCIM_BEARER_TOKEN"
```

---

#### `GET /scim/v2/Users` — List / filter users

**Query parameters**

| Parameter | Default | Description |
|---|---|---|
| `startIndex` | `1` | 1-based result offset |
| `count` | `100` | Max results per page (hard cap `200`) |
| `filter` | — | SCIM filter expression |

**Supported filter attributes**

| SCIM attribute | D1 column |
|---|---|
| `userName` | `user_name` |
| `externalId` | `external_id` |
| `active` | `active` |
| `displayName` | `display_name` |

Supported operators: `eq`, `pr` (present), and compound `and`. All filter
values are passed as SQL bind parameters — never interpolated into the query.
The filter expression is length-capped at 2048 characters and depth-capped at
16 nested levels.

**Response `200 OK`**

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 42,
  "startIndex": 1,
  "itemsPerPage": 20,
  "Resources": [...]
}
```

**Filter examples**

```bash
# Find by userName
curl -s "https://idp.lifecycle.example/scim/v2/Users?filter=userName+eq+%22alice%40acme.example%22" \
  -H "Authorization: Bearer $SCIM_BEARER_TOKEN"

# Find by externalId
curl -s "https://idp.lifecycle.example/scim/v2/Users?filter=externalId+eq+%22okta-00u1abc%22" \
  -H "Authorization: Bearer $SCIM_BEARER_TOKEN"

# Compound filter
curl -s "https://idp.lifecycle.example/scim/v2/Users?filter=active+eq+%22true%22+and+displayName+pr" \
  -H "Authorization: Bearer $SCIM_BEARER_TOKEN"
```

---

#### `PUT /scim/v2/Users/:id` — Replace user

Full replacement of the user resource. `id` in the URL must match `id` in the
body (if present). The `version` column is incremented; the new `ETag` is
returned in the response.

**Response `200 OK`** — full replaced resource  
**Response `404 Not Found`** — user does not exist for this tenant  
**Response `412 Precondition Failed`** — `If-Match` ETag mismatch (optimistic concurrency)

**curl example**

```bash
curl -s -X PUT https://idp.lifecycle.example/scim/v2/Users/2819c223-7f76-453a-919d-413861904646 \
  -H "Authorization: Bearer $SCIM_BEARER_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -H "If-Match: W/\"1\"" \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@acme.example","active":true}'
```

---

#### `PATCH /scim/v2/Users/:id` — Partial update

RFC 7644 §3.5.2 PATCH with `PatchOp`. Atomic — all operations are applied or
none. Supports `add`, `replace`, and `remove`. The engine handles:
- Dot-path navigation (`name.givenName`)
- URN-extension keys (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`)
  kept atomic (no dot-splitting)
- Member-remove from `members` array by filter (`members[value eq "X"]`)
- `active: "false"` string coercion (Okta sends `active` as a string)

**Soft-delete pattern (Okta/Entra deprovisioning)**

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {"op": "replace", "path": "active", "value": false}
  ]
}
```

**Response `200 OK`** — full updated resource  
**Response `404 Not Found`**  
**Response `400 Bad Request`** — invalid op, path, or value

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "400",
  "scimType": "invalidValue",
  "detail": "Cannot remove required attribute: userName"
}
```

**curl example**

```bash
curl -s -X PATCH https://idp.lifecycle.example/scim/v2/Users/2819c223-7f76-453a-919d-413861904646 \
  -H "Authorization: Bearer $SCIM_BEARER_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "replace", "path": "active", "value": false}
    ]
  }'
```

---

#### `DELETE /scim/v2/Users/:id` — Hard delete

Permanently removes the user row from D1. Okta and Entra prefer soft-delete
(`PATCH active=false`) over hard delete for lifecycle management.

**Response `204 No Content`** — deleted  
**Response `404 Not Found`** — no such user for this tenant

**curl example**

```bash
curl -s -X DELETE https://idp.lifecycle.example/scim/v2/Users/2819c223-7f76-453a-919d-413861904646 \
  -H "Authorization: Bearer $SCIM_BEARER_TOKEN"
```

---

### 9.3 Groups

The Groups collection (`/scim/v2/Groups`) is declared in `ResourceTypes` and
the D1 schema (`scim_groups` table) exists, but the WASM dispatch layer for
Group CRUD is not yet wired. All group routes currently return `404 Not Found`.

---

### 9.4 SCIM error schema

All SCIM error responses use this envelope (RFC 7644 §3.12). Note `status` is a
string:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "400",
  "scimType": "invalidFilter",
  "detail": "Unsupported filter operator: gt"
}
```

**`scimType` values**

| Value | Meaning |
|---|---|
| `uniqueness` | Attribute must be unique; conflict on create/replace |
| `mutability` | Attribute is immutable and cannot be changed |
| `invalidFilter` | Filter expression is syntactically or semantically invalid |
| `invalidPath` | PATCH path is invalid |
| `invalidSyntax` | Request body cannot be parsed |
| `invalidValue` | Attribute value fails validation |
| `noTarget` | PATCH remove target does not match any member |
| `tooMany` | Too many results; narrow the filter |
| `sensitive` | Attribute not returned for security reasons |

---

## 10. Live Telemetry SSE Stream

### `GET /api/telemetry/stream`

Server-Sent Events stream of `TelemetryEvent` objects emitted by the edge
engine. Events are aggregated in the `TELEMETRY_DO` Durable Object (ring buffer)
and fanned out to all connected subscribers. Reconnection is supported via the
`Last-Event-ID` header — the DO replays all buffered events since the given ID.

**Auth required:** No (served from the `site` Astro worker; gated by the edge
service binding in production)

**Response `200 OK`**

| Header | Value |
|---|---|
| `Content-Type` | `text/event-stream; charset=utf-8` |
| `Cache-Control` | `no-cache, no-transform` |
| `Connection` | `keep-alive` |

**Wire format**

```
retry: 3000

id: 1
data: {"v":1,"id":"1","ts":1750000001000,"node":"edge","edge":"idp-edge","phase":"authn","label":"OIDC code exchange"}

id: 2
data: {"v":1,"id":"2","ts":1750000002000,"node":"opa","edge":"edge-opa","phase":"authz","label":"policy eval"}

id: 3
data: {"v":1,"id":"3","ts":1750000003000,"node":"aws","edge":"edge-aws","phase":"federation","label":"STS exchange"}

: keepalive

```

**Reconnection with replay**

```bash
curl -N https://idp.lifecycle.example/api/telemetry/stream \
  -H "Last-Event-ID: 42"
# The DO replays all events with id > 42 before streaming live events.
```

---

### `POST /api/telemetry/demo` — Demo trigger

Enqueues a scripted sequence of `TelemetryEvent` objects to the `TELEMETRY_QUEUE`
Queue binding, simulating a complete JML lifecycle event (hire → provision →
federate → deprovision) for the live 3D graph visualization.

**Auth required:** No (rate-limited by Cloudflare)

**Response `202 Accepted`**

```json
{"ok": true}
```

**Response `502 Bad Gateway`** — edge service binding unavailable

```json
{"ok": false, "error": "upstream error"}
```

**curl example**

```bash
curl -s -X POST https://idp.lifecycle.example/api/telemetry/demo
```

---

## Appendix A: Cloudflare Secret bindings

| Secret name | Used by | Description |
|---|---|---|
| `INTERNAL_ED25519_SEED` | `/jwks`, internal token minting | 64 hex-char Ed25519 seed (32 bytes) |
| `CLOUD_RSA_PKCS8_DER_B64` | `POST /federate` | Base64url PKCS8 DER RSA private key for cloud RS256 |
| `SCIM_BEARER_TOKEN` | `/scim/v2/**` | SCIM bearer secret (constant-time verified) |
| `SCIM_TENANT_ID` | `/scim/v2/**` | Tenant ID that the SCIM bearer is scoped to |
| `FEDERATION_API_TOKEN` | `POST /federate` | Bearer token for control-plane callers |
| `INTROSPECT_BEARER_TOKEN` | `POST /introspect` | Bearer token for introspection callers |
| `AUTHZ_BUNDLE` | `POST /decision` | Signed JSON policy bundle (Rego + data) |
| `AUTHZ_BUNDLE_SIG` | `POST /decision` | Detached Ed25519 signature over bundle (base64url) |
| `AUTHZ_BUNDLE_PUBKEY` | `POST /decision` | 64-char hex Ed25519 public key for bundle verification |

## Appendix B: Cloudflare bindings (non-secret)

| Binding | Type | Purpose |
|---|---|---|
| `SESSIONS` | Durable Object (`SessionStore`) | Session lifecycle: create / revoke / resolve |
| `DB` | D1 (`lifecycle`) | SCIM user/group persistent store |
| `JWKS_CACHE` | KV namespace | RP state/nonce stash + RSA JWK cache |
| `TELEMETRY_QUEUE` | Queue (producer) | Telemetry event ingestion |
| `TELEMETRY_DO` | Durable Object | Event ring buffer + SSE fan-out |

## Appendix C: Status code summary

| Code | Meaning in Tessera |
|---|---|
| `200` | OK (also used for all authz decision responses) |
| `201` | SCIM resource created |
| `202` | Demo trigger accepted |
| `204` | SCIM resource deleted |
| `302` | OIDC authorize redirect |
| `400` | Bad request / invalid input |
| `401` | Missing or wrong bearer token |
| `404` | Resource not found (also: cross-tenant BOLA) |
| `409` | SCIM uniqueness conflict |
| `412` | ETag precondition failed (SCIM optimistic concurrency) |
| `500` | JWKS invariant violation or unexpected engine error |
