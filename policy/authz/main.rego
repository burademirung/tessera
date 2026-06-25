# METADATA
# title: Lifecycle authorization decision
# description: Role-centric RBAC-A. Role sets the envelope; ABAC only narrows.
# entrypoint: true
package authz

# Deny-by-default (NIST 800-207 fail-closed; OWASP ASVS V8).
default allow := false

# The single hot-path decision the PEP queries as `data.authz.allow`.
# Filled in by Task 2 (RBAC envelope) and Task 3 (ABAC narrowing).
allow if {
	role_permits
	abac_ok
}

# role_permits is defined in rbac.rego (Task 2); the default keeps it a total
# function so tests can bind `got := role_permits` even when no permission matches.
default role_permits := false

# abac_ok is defined in abac.rego (Task 3).
default abac_ok := false
