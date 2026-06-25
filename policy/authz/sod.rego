# Separation of Duties (NIST AC-5; INCITS 359 SSD/DSD).
# Preventive at request time; detective over replay sweeps.
package authz

# --- Preventive (request-time): true if THIS request is a SoD violation. ---
sod_conflict if {
	holds_toxic_pair(role_set(input.subject.roles))
}

sod_conflict if {
	input.action in data.sod.self_approval_actions
	input.resource.requester == input.subject.id
}

role_set(roles) := {r | some r in roles}

holds_toxic_pair(roles) if {
	some pair in data.sod.toxic_pairs
	pair[0] in roles
	pair[1] in roles
}

# --- Detective (replay sweep): set of all violations across input.assignments + input.review. ---
sod_findings contains finding if {
	some a in input.assignments
	holds_toxic_pair(role_set(a.roles))
	finding := {
		"kind": "toxic_role_pair",
		"subject": a.subject,
		"roles": a.roles,
	}
}

sod_findings contains finding if {
	some r in input.review
	r.requester == r.approver
	finding := {
		"kind": "self_approval",
		"request_id": r.request_id,
		"subject": r.approver,
	}
}
