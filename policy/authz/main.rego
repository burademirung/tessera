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
	not sod_conflict
}

# role_permits is defined in rbac.rego (Task 2); abac_ok in abac.rego (Task 3).
# The defaults keep both total so tests can bind `got := <rule>` even when the
# conditional body does not hold (otherwise `got` would be undefined).
default role_permits := false

default abac_ok := false
