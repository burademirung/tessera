# Wiring to Okta + Microsoft Entra ID (Free/Dev Tiers)

Engine = OIDC RP + SAML SP (consuming Okta/Entra) + SCIM 2.0 service provider (they push into it).

## Free-tier verdict
| Capability | Okta Integrator Free | Entra ID Free |
|---|---|---|
| OIDC RP (Auth Code+PKCE) | Yes | Yes |
| SAML SSO custom app | Yes | Yes (**single-tenant only**) |
| SCIM **user** provisioning | Yes (10 active users) | Yes |
| SCIM **group** provisioning | Yes | **No (P1)** |
| Provisioning logs | Yes | **No (P1/P2)** |
Build OIDC+SAML+SCIM user provisioning on free tiers; use **30-day Entra P2 trial** for group provisioning/logs in the demo.

## OIDC
**Okta:** Create App Integration → OIDC → Web App (secret + enable PKCE). Auth methods: client_secret_basic/post/jwt, private_key_jwt, none. Redirect URIs absolute HTTPS (http only localhost). **Use the `default` custom authorization server** (`/oauth2/default/.well-known/openid-configuration`); **free-tier gotcha: default AS has no access policy — add one** or no tokens. Web app refresh: enable "Rotate token after every use." 
**Entra:** App registrations → Web (confidential) or SPA (PKCE mandatory, 24h refresh). v2 endpoints (`/{tenant}/v2.0/.well-known/openid-configuration`, JWKS `/discovery/v2.0/keys`, userinfo on Graph). Redirect HTTPS (localhost port ignored, differ by path), ≤256 URIs. Scopes `openid profile email offline_access`. Pure code flow doesn't need the "ID tokens (implicit)" checkbox.

## SAML
**Okta:** SAML 2.0 app → SSO URL (ACS) + Audience URI (SP entity id); assertion signed SHA256 by default; optional signed AuthnRequest; View IdP metadata. **Entra:** Enterprise app → "Integrate any other application (Non-gallery)" → SAML (**greyed out for multi-tenant — register single-tenant**); download Federation Metadata XML; default NameID `userprincipalname`/emailAddress. Token encryption needs P1/P2.

## SCIM — what each requires (verbatim-verified)
**Okta:** calls `/Users` (GET filter+paged, GET/{id}, POST, PUT, PATCH), `/Groups` (incl. DELETE for groups). Discovery endpoints NOT required. Never DELETEs users (deactivate via PATCH **or PUT** — support both). Filter `eq`. Pagination `startIndex` 1-based, counts **integers**. Deactivate PATCH: `replace` **no path**, value `{"active":false}` (boolean). Group member remove: `path:"members[value eq \"...\"]"`; add: `path:"members"`. Auth Basic/Bearer/OAuth. Test via "SCIM 2.0 Test App"; compliance = Runscope `Okta-SCIM-20-CRUD-Test.json`.
**Entra:** Tenant URL ends `/scim`; `Content-Type: application/scim+json`; **TLS 1.2 + public CA**. Test Connection = GET random GUID → **200 empty ListResponse, not 404**. Schema discovery NOT supported for non-gallery (manual mappings). Operators `eq`,`and`. **Default match attribute `externalId`.** Status: create 201, dup 409, found 200, query 200+ListResponse, PATCH user 200, **PATCH group 204**, DELETE 204. **DUAL-DIALECT PATCH (must handle both, flag `aadOptscim062020`):** without flag → capitalized `op`, `active` value is **string `"False"`**; with flag → lowercase `op`, boolean `false`, replace-without-path multi-attr value with dot-notation keys. Deprovision = `active:false` soft delete (still GET-able); DELETE only on hard removal. Auth long-lived bearer or OAuth2 client-creds.

## Server must absorb (to pass both)
1. `op.to_lowercase()`. 2. `active` accepts boolean AND `"True"/"False"`. 3. `replace` with/without `path` (split dot-notation). 4. group remove both value-array and `members[value eq ...]`. 5. never hard-delete on `active:false`. 6. match `userName` AND `externalId`; zero → 200 empty (never 404); integer counts. 7. `application/scim+json`, TLS1.2+ public CA. 8. PUT and PATCH on `/Users/{id}`.

## Validators / CI
Microsoft SCIM Validator (https://scimvalidator.microsoft.com/, no API — manual gate) + .NET SCIM reference; Okta Runscope CRUD. CI: Rust integration test replaying **verbatim payloads from both vendors (both Entra dialects + Okta no-path replace)** asserting the status-code matrix.

## Free-tier caveats
Okta: 10 active users, default-AS needs policy, org deactivates after 180 days idle. Entra: user provisioning + SAML (single-tenant) free; group provisioning/logs need P1 (use 30-day P2 trial).
