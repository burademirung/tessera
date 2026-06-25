// Canonical requirement-map / §6 coverage keys. The site MUST have one
// content entry per key (enforced by the coverage test in Task 8).
export const REQUIRED_TECH_KEYS = [
  'go',
  'rust',
  'terraform',
  'aws-cdk',
  'oidc',
  'saml',
  'oauth',
  'scim',
  'jwt',
  'workload-identity-federation',
  'opa-rego',
  'rbac-abac',
  'zero-trust',
  'cloudflare-workers',
  'cicd-slsa',
  'frontend-3d-wcag',
] as const;

export type TechKey = (typeof REQUIRED_TECH_KEYS)[number];
