package authz_test

import data.authz

# Default deny: an empty request, with no roles/permissions, must be denied.
test_default_deny_empty_input if {
	not authz.allow with input as {}
}

# Default deny: even a fully-formed request denies when no data backs it.
test_default_deny_no_data if {
	req := {
		"subject": {"id": "u1", "roles": ["nobody"], "tenant": "t1", "mfa": true},
		"resource": {"type": "user", "id": "u9", "tenant": "t1"},
		"action": "read",
		"environment": {"now": "2026-06-24T00:00:00Z", "now_epoch": 1782259200},
	}

	not authz.allow with input as req with data.rbac as {} with data.sod as {}
}
