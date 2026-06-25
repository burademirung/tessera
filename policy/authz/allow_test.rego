package authz_test

import data.authz

# Explicit, named default-deny (mirrors Task 1 but at the full `allow` surface).
test_allow_default_deny if {
	not authz.allow with input as {} with data.rbac as {} with data.abac as {} with data.sod as {}
}
