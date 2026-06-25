# SAML — brokered to OIDC, never hand-rolled in WASM

The edge engine does **not** parse or verify SAML XML / XML-DSig. Per the design
spec (§4.1, §6) and research brief 07/10:

- `samael`/`bergshamra`/`xml-sec` rely on xmlsec1/libxml2/OpenSSL and do **not**
  build on `wasm32-unknown-unknown`.
- XML Signature Wrapping and parser-differential CVEs (CVE-2025-25291/25292,
  CVE-2025-66567/66568) make hand-rolled c14n/verification unsafe.

**Boundary:** any SAML IdP is fronted by a broker (Cloudflare Access / WorkOS /
Keycloak) that converts SAML -> OIDC. The Worker then consumes OIDC only, using
the RP path built in Task 7 (PKCE S256, state, nonce, RFC 9207 `iss`). The Worker
is kept entirely out of the XML trust path.

If SAML ever becomes mandatory in-process, it must be isolated off-WASM in a
single hardened library with parse-once / verify-and-consume-the-same-tree /
DTD-disabled / reject-multi-assertion semantics — out of scope for this phase.
