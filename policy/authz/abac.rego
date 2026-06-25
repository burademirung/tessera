# ABAC narrowing constraints (NIST SP 800-162).
# Constraints only narrow the RBAC envelope; they never expand it.
package authz

# abac_ok holds iff EVERY constraint holds. Each constraint defaults to
# satisfied; a violated constraint adds to `abac_violations`, which fails the gate.
abac_ok if {
	count(abac_violations) == 0
}

# 1. Tenant isolation (BOLA): subject and resource tenant must match exactly.
abac_violations contains "tenant_mismatch" if {
	input.subject.tenant != input.resource.tenant
}

# 2. Step-up MFA for sensitive actions.
abac_violations contains "mfa_required" if {
	input.action in data.abac.mfa_required_actions
	not input.subject.mfa == true
}

# 3. Device posture floor for high-risk actions.
abac_violations contains "device_posture" if {
	required := data.abac.min_device_posture[input.action]
	have := object.get(data.abac.posture_rank, input.environment.device_posture, -1)
	need := object.get(data.abac.posture_rank, required, 1000)
	have < need
}

# 4. Maintenance window for the resource type (0/0 window = no restriction).
abac_violations contains "outside_maintenance_window" if {
	win := data.abac.maintenance_windows[input.resource.type]
	win.start_epoch != win.end_epoch
	not within_window(input.environment.now_epoch, win)
}

within_window(now, win) if {
	now >= win.start_epoch
	now <= win.end_epoch
}
