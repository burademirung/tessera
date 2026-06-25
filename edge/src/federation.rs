//! Cloud-federation token claims (RS256). Pure claim construction is host-tested;
//! actual RS256 signing is done via WebCrypto in `webcrypto_rsa` (Task 5).

use serde_json::{json, Value};
use subtle::ConstantTimeEq;

/// Authenticate the internal caller of `/federate`. The Go control-plane presents
/// `Authorization: Bearer <FEDERATION_API_TOKEN>`; the secret is configured as a
/// Worker secret. FAIL-CLOSED:
/// - missing/empty configured secret -> false (never default-allow)
/// - missing/non-Bearer header        -> false
/// - empty presented token            -> false
/// - mismatch                         -> false
///
/// The comparison is CONSTANT-TIME (subtle::ct_eq) to avoid leaking the secret via
/// timing. Length is not secret, so a fast length pre-check is fine. Pure +
/// host-testable; the wasm call site reads `expected` from the Worker secret.
pub fn caller_is_authorized(auth_header: Option<&str>, expected: &str) -> bool {
    if expected.is_empty() {
        return false; // secret not configured -> fail closed, mint nothing
    }
    let presented = match auth_header.and_then(|h| h.strip_prefix("Bearer ")) {
        Some(t) if !t.is_empty() => t,
        _ => return false,
    };
    if presented.len() != expected.len() {
        return false;
    }
    presented.as_bytes().ct_eq(expected.as_bytes()).into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cloud {
    Aws,
    Azure,
    Gcp,
}

#[derive(Clone, Debug)]
pub struct CloudAudiences {
    pub aws: String,
    pub azure: String,
    pub gcp: String,
}

impl CloudAudiences {
    /// Canonical per-cloud audiences. AWS STS, the Azure required constant, and a
    /// GCP workload-identity provider resource URL. (The GCP value is a deployment
    /// placeholder resource path; replace the project/pool/provider before deploy.)
    pub fn production() -> Self {
        CloudAudiences {
            aws: "sts.amazonaws.com".into(),
            azure: "api://AzureADTokenExchange".into(),
            gcp: "//iam.googleapis.com/projects/000000000000/locations/global/workloadIdentityPools/tessera-pool/providers/tessera-oidc".into(),
        }
    }
}

/// The distinct `aud` for each cloud. A token is NEVER reused across clouds.
pub fn audience_for(cfg: &CloudAudiences, cloud: Cloud) -> &str {
    match cloud {
        Cloud::Aws => &cfg.aws,
        Cloud::Azure => &cfg.azure,
        Cloud::Gcp => &cfg.gcp,
    }
}

/// Parse a cloud identifier from the federation request body.
pub fn parse_cloud(s: &str) -> Option<Cloud> {
    match s.trim().to_ascii_lowercase().as_str() {
        "aws" => Some(Cloud::Aws),
        "azure" => Some(Cloud::Azure),
        "gcp" => Some(Cloud::Gcp),
        _ => None,
    }
}

const MAX_SUB_LEN: usize = 127; // GCP limit
const MAX_TTL_SECS: u64 = 86_400; // GCP: exp - iat <= 24h

/// Build RS256 federation claims for exactly one cloud. Enforces the cross-cloud
/// constraints: distinct `aud`, `sub` <= 127 chars, no `azp` (AWS treats it as
/// audience), required iss/iat/exp/nbf, minutes-to-24h lifetime.
pub fn build_federation_claims(
    cfg: &CloudAudiences,
    cloud: Cloud,
    iss: &str,
    sub: &str,
    now: u64,
    ttl_secs: u64,
) -> Result<Value, String> {
    if sub.is_empty() {
        return Err("sub must be non-empty".to_string());
    }
    if sub.len() > MAX_SUB_LEN {
        return Err(format!("sub too long: {} > {MAX_SUB_LEN}", sub.len()));
    }
    if ttl_secs == 0 || ttl_secs > MAX_TTL_SECS {
        return Err(format!("ttl {ttl_secs} out of range (1..={MAX_TTL_SECS})"));
    }
    Ok(json!({
        "iss": iss,
        "sub": sub,
        "aud": audience_for(cfg, cloud),
        "iat": now,
        "nbf": now,
        "exp": now + ttl_secs,
    }))
}

/// JOSE header for RS256 cloud tokens (typ JWT; kid for JWKS rotation).
pub fn rs256_signing_header(kid: &str) -> Value {
    json!({ "alg": "RS256", "typ": "JWT", "kid": kid })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_750_000_000;

    fn auds() -> CloudAudiences {
        CloudAudiences {
            aws: "sts.amazonaws.com".into(),
            azure: "api://AzureADTokenExchange".into(),
            gcp: "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/tessera-pool/providers/tessera-oidc".into(),
        }
    }

    #[test]
    fn each_cloud_gets_a_distinct_audience() {
        let cfg = auds();
        assert_eq!(audience_for(&cfg, Cloud::Aws), cfg.aws);
        assert_eq!(audience_for(&cfg, Cloud::Azure), cfg.azure);
        assert_eq!(audience_for(&cfg, Cloud::Gcp), cfg.gcp);
        assert_ne!(
            audience_for(&cfg, Cloud::Aws),
            audience_for(&cfg, Cloud::Azure)
        );
    }

    #[test]
    fn azure_audience_is_the_required_constant() {
        assert_eq!(
            audience_for(&auds(), Cloud::Azure),
            "api://AzureADTokenExchange"
        );
    }

    #[test]
    fn builds_claims_with_correct_aud_and_no_azp() {
        let cfg = auds();
        let c = build_federation_claims(
            &cfg,
            Cloud::Gcp,
            "https://idp.tessera.example",
            "tenant-a:wl-1",
            NOW,
            900,
        )
        .unwrap();
        assert_eq!(c["aud"], cfg.gcp);
        assert_eq!(c["iss"], "https://idp.tessera.example");
        assert_eq!(c["sub"], "tenant-a:wl-1");
        assert_eq!(c["exp"].as_u64().unwrap(), NOW + 900);
        assert!(
            c.get("azp").is_none(),
            "AWS treats azp as audience; must omit"
        );
    }

    #[test]
    fn rejects_sub_over_127_chars() {
        let cfg = auds();
        let long = "x".repeat(128);
        assert!(build_federation_claims(
            &cfg,
            Cloud::Aws,
            "https://idp.tessera.example",
            &long,
            NOW,
            900
        )
        .is_err());
    }

    #[test]
    fn rejects_ttl_over_24h_for_gcp_limit() {
        let cfg = auds();
        assert!(build_federation_claims(
            &cfg,
            Cloud::Gcp,
            "https://idp.tessera.example",
            "s",
            NOW,
            86_401
        )
        .is_err());
    }

    #[test]
    fn rs256_header_declares_rs256_and_kid() {
        let h = rs256_signing_header("cloud-2026-06");
        assert_eq!(h["alg"], "RS256");
        assert_eq!(h["typ"], "JWT");
        assert_eq!(h["kid"], "cloud-2026-06");
    }

    #[test]
    fn federate_caller_auth_fails_closed_without_correct_token() {
        // No header -> rejected.
        assert!(!caller_is_authorized(None, "fed-secret"));
        // Non-Bearer scheme -> rejected.
        assert!(!caller_is_authorized(
            Some("Basic fed-secret"),
            "fed-secret"
        ));
        // Empty presented token -> rejected.
        assert!(!caller_is_authorized(Some("Bearer "), "fed-secret"));
        // Wrong token (same length) -> rejected.
        assert!(!caller_is_authorized(
            Some("Bearer fed-secreX"),
            "fed-secret"
        ));
        // Wrong token (diff length) -> rejected.
        assert!(!caller_is_authorized(Some("Bearer nope"), "fed-secret"));
        // Unconfigured secret must never authenticate, even an empty token.
        assert!(!caller_is_authorized(Some("Bearer "), ""));
        assert!(!caller_is_authorized(Some("Bearer anything"), ""));
    }

    #[test]
    fn federate_caller_auth_accepts_correct_token() {
        assert!(caller_is_authorized(
            Some("Bearer fed-secret"),
            "fed-secret"
        ));
    }

    #[test]
    fn parse_cloud_handles_known_and_unknown() {
        assert_eq!(parse_cloud("aws"), Some(Cloud::Aws));
        assert_eq!(parse_cloud("azure"), Some(Cloud::Azure));
        assert_eq!(parse_cloud("gcp"), Some(Cloud::Gcp));
        assert_eq!(parse_cloud("GCP"), Some(Cloud::Gcp));
        assert_eq!(parse_cloud("oracle"), None);
    }
}
