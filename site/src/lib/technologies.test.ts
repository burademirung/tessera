// @vitest-environment node
import { describe, it, expect } from 'vitest';
import { REQUIRED_TECH_KEYS } from './technologies';

describe('REQUIRED_TECH_KEYS', () => {
  it('covers every spec requirement-map / §6 technology', () => {
    expect([...REQUIRED_TECH_KEYS].sort()).toEqual(
      [
        'aws-cdk',
        'cicd-slsa',
        'cloudflare-workers',
        'frontend-3d-wcag',
        'go',
        'jwt',
        'oauth',
        'oidc',
        'opa-rego',
        'rbac-abac',
        'rust',
        'saml',
        'scim',
        'terraform',
        'workload-identity-federation',
        'zero-trust',
      ].sort(),
    );
  });
  it('has no duplicate keys', () => {
    expect(new Set(REQUIRED_TECH_KEYS).size).toBe(REQUIRED_TECH_KEYS.length);
  });
});
