package authz_test

import data.authz

abac_fixture := data.abac_fixture.abac

base_req(overrides) := object.union(
	{
		"subject": {"id": "u1", "roles": ["admin"], "tenant": "t1", "mfa": true},
		"resource": {"type": "user", "id": "r1", "tenant": "t1"},
		"action": "read",
		"environment": {"now_epoch": 1782259200, "device_posture": "managed"},
	},
	overrides,
)

abac_cases := [
	{"name": "same tenant, read, ok", "ov": {}, "want": true},
	{"name": "cross-tenant denied", "ov": {"resource": {"type": "user", "id": "r1", "tenant": "t2"}}, "want": false},
	{"name": "mfa-required action without mfa denied", "ov": {"action": "delete", "subject": {"id": "u1", "roles": ["admin"], "tenant": "t1", "mfa": false}}, "want": false},
	{"name": "mfa-required action with mfa ok", "ov": {"action": "delete"}, "want": true},
	{"name": "read needs no mfa", "ov": {"subject": {"id": "u1", "roles": ["admin"], "tenant": "t1", "mfa": false}}, "want": true},
	{"name": "delete from unmanaged device denied", "ov": {"action": "delete", "environment": {"now_epoch": 1782259200, "device_posture": "unmanaged"}}, "want": false},
	{"name": "delete from managed device ok", "ov": {"action": "delete"}, "want": true},
]

test_abac_ok_table if {
	every case in abac_cases {
		got := authz.abac_ok with input as base_req(case.ov) with data.abac as abac_fixture
		got == case.want
	}
}

# Maintenance window: policy writes only inside an active window.
test_maintenance_window_blocks_outside if {
	win := object.union(abac_fixture, {"maintenance_windows": {"policy": {"start_epoch": 2000000000, "end_epoch": 2000003600}}})
	req := base_req({"resource": {"type": "policy", "id": "p1", "tenant": "t1"}, "action": "update"})
	not authz.abac_ok with input as req with data.abac as win
}

test_maintenance_window_allows_inside if {
	win := object.union(abac_fixture, {"maintenance_windows": {"policy": {"start_epoch": 1782259000, "end_epoch": 1782262800}}})
	req := base_req({"resource": {"type": "policy", "id": "p1", "tenant": "t1"}, "action": "update"})
	authz.abac_ok with input as req with data.abac as win
}
