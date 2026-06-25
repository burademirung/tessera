# RBAC role envelope (NIST INCITS 359 Hierarchical RBAC).
package authz

# Transitive closure of a role's inherited roles (incl. itself).
effective_roles(role) := {r | some r in graph.reachable(role_inheritance, {role})}

# Adjacency for graph.reachable: role -> set of roles it inherits.
role_inheritance[role] := inherited if {
	some role, def in data.rbac.roles
	inherited := {i | some i in def.inherits}
}

# All permissions carried by the subject's directly-assigned roles, expanded
# through inheritance. A permission is {resource, action}.
subject_permissions contains perm if {
	some assigned in input.subject.roles
	some role in effective_roles(assigned)
	some perm in data.rbac.roles[role].permissions
}

# The RBAC envelope: some effective role carries a permission matching the
# requested resource type + action. This is the upper bound; ABAC narrows it.
role_permits if {
	some perm in subject_permissions
	perm.resource == input.resource.type
	perm.action == input.action
}
