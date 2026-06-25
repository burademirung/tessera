package authz_test

import data.authz

rbac_fixture := data.rbac_fixture

# Table-driven: subject roles + resource/action → expected role_permits.
rbac_cases := [
	{"name": "reader reads user", "roles": ["reader"], "type": "user", "action": "read", "want": true},
	{"name": "reader cannot delete user", "roles": ["reader"], "type": "user", "action": "delete", "want": false},
	{"name": "helpdesk inherits reader read", "roles": ["helpdesk"], "type": "group", "action": "read", "want": true},
	{"name": "helpdesk updates user", "roles": ["helpdesk"], "type": "user", "action": "update", "want": true},
	{"name": "admin inherits delete via deep chain", "roles": ["admin"], "type": "user", "action": "delete", "want": true},
	{"name": "admin inherits approve transitively", "roles": ["admin"], "type": "access_request", "action": "approve", "want": true},
	{"name": "provisioner cannot revoke sessions", "roles": ["provisioner"], "type": "session", "action": "revoke", "want": false},
	{"name": "unknown role grants nothing", "roles": ["ghost"], "type": "user", "action": "read", "want": false},
	{"name": "no roles grants nothing", "roles": [], "type": "user", "action": "read", "want": false},
]

test_role_permits_table if {
	every case in rbac_cases {
		req := {
			"subject": {"id": "u1", "roles": case.roles, "tenant": "t1"},
			"resource": {"type": case.type, "id": "r1", "tenant": "t1"},
			"action": case.action,
			"environment": {},
		}
		got := authz.role_permits with input as req with data.rbac as rbac_fixture.rbac
		got == case.want
	}
}
