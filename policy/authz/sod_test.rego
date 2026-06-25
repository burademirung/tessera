package authz_test

import data.authz

sod_fixture := data.sod_fixture.sod

# --- Preventive (request-time) ---
test_sod_conflict_toxic_role_pair if {
	req := {
		"subject": {"id": "u1", "roles": ["provisioner", "approver"], "tenant": "t1"},
		"resource": {"type": "access_request", "id": "ar1", "tenant": "t1"},
		"action": "approve",
		"environment": {},
	}
	authz.sod_conflict with input as req with data.sod as sod_fixture
}

test_sod_conflict_self_approval if {
	req := {
		"subject": {"id": "u1", "roles": ["approver"], "tenant": "t1"},
		"resource": {"type": "access_request", "id": "ar1", "tenant": "t1", "requester": "u1"},
		"action": "approve",
		"environment": {},
	}
	authz.sod_conflict with input as req with data.sod as sod_fixture
}

test_no_sod_conflict_clean if {
	req := {
		"subject": {"id": "u2", "roles": ["approver"], "tenant": "t1"},
		"resource": {"type": "access_request", "id": "ar1", "tenant": "t1", "requester": "u1"},
		"action": "approve",
		"environment": {},
	}
	not authz.sod_conflict with input as req with data.sod as sod_fixture
}

# --- Detective (replay sweep) ---
test_sod_findings_detect_toxic_assignment if {
	sweep := {
		"assignments": [
			{"subject": "u1", "roles": ["provisioner", "approver"]},
			{"subject": "u2", "roles": ["reader"]},
		],
		"review": [],
	}
	findings := authz.sod_findings with input as sweep with data.sod as sod_fixture
	count(findings) == 1
	some f in findings
	f.subject == "u1"
	f.kind == "toxic_role_pair"
}

test_sod_findings_detect_self_approval if {
	sweep := {
		"assignments": [],
		"review": [{"request_id": "ar9", "requester": "u3", "approver": "u3"}],
	}
	findings := authz.sod_findings with input as sweep with data.sod as sod_fixture
	count(findings) == 1
	some f in findings
	f.kind == "self_approval"
	f.request_id == "ar9"
}

test_sod_findings_clean_is_empty if {
	sweep := {"assignments": [{"subject": "u2", "roles": ["reader"]}], "review": [{"request_id": "ar1", "requester": "u1", "approver": "u2"}]}
	findings := authz.sod_findings with input as sweep with data.sod as sod_fixture
	count(findings) == 0
}
