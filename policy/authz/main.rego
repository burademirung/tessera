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

# Placeholders replaced with real logic in Tasks 2 and 3.
# Until then they are deliberately undefined so `allow` stays false.
default role_permits := false

default abac_ok := false
