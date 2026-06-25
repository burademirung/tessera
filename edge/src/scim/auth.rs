//! Verify-first bearer/OAuth auth + tenant resolution + object-level (BOLA) scoping.
//! The actual token verification is injected (Phase-2 engine); this module is the
//! pure policy: require Bearer, resolve tenant, hide cross-tenant resources as 404.

use crate::scim::error::ScimError;

#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedToken {
    pub tenant_id: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TenantCtx {
    pub tenant_id: String,
    pub scopes: Vec<String>,
}

pub fn resolve_tenant(
    authorization: Option<&str>,
    verify: &dyn Fn(&str) -> Option<VerifiedToken>,
) -> Result<TenantCtx, ScimError> {
    let header = authorization.ok_or_else(|| ScimError::unauthorized("missing Authorization"))?;
    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ScimError::unauthorized("expected Bearer token"))?;
    let verified = verify(token).ok_or_else(|| ScimError::unauthorized("invalid token"))?;
    Ok(TenantCtx {
        tenant_id: verified.tenant_id,
        scopes: verified.scopes,
    })
}

/// Cross-tenant access is hidden as 404, never 403 (no existence disclosure).
pub fn ensure_owns(ctx: &TenantCtx, resource_tenant: &str) -> Result<(), ScimError> {
    if ctx.tenant_id == resource_tenant {
        Ok(())
    } else {
        Err(ScimError::not_found("resource not found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier(token: &str) -> Option<VerifiedToken> {
        if token == "good" {
            Some(VerifiedToken {
                tenant_id: "t1".into(),
                scopes: vec!["scim".into()],
            })
        } else {
            None
        }
    }

    #[test]
    fn missing_authorization_is_401() {
        let err = resolve_tenant(None, &verifier).unwrap_err();
        assert_eq!(err.status, 401);
    }

    #[test]
    fn non_bearer_is_401() {
        let err = resolve_tenant(Some("Basic abc"), &verifier).unwrap_err();
        assert_eq!(err.status, 401);
    }

    #[test]
    fn invalid_token_is_401() {
        let err = resolve_tenant(Some("Bearer bad"), &verifier).unwrap_err();
        assert_eq!(err.status, 401);
    }

    #[test]
    fn valid_token_resolves_tenant() {
        let ctx = resolve_tenant(Some("Bearer good"), &verifier).unwrap();
        assert_eq!(ctx.tenant_id, "t1");
    }

    #[test]
    fn cross_tenant_access_is_404_not_403() {
        let ctx = TenantCtx {
            tenant_id: "t1".into(),
            scopes: vec![],
        };
        let err = ensure_owns(&ctx, "t2").unwrap_err();
        assert_eq!(err.status, 404); // BOLA: hide existence
    }

    #[test]
    fn same_tenant_access_ok() {
        let ctx = TenantCtx {
            tenant_id: "t1".into(),
            scopes: vec![],
        };
        assert!(ensure_owns(&ctx, "t1").is_ok());
    }
}
