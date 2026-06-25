package authz_test

import data.authz

# Drives the SAME vectors the Regorus conformance harness uses (Task 8).
# opa merges policy/conformance/vectors.json's top-level keys at the data root,
# so the bundle is reachable via data.vectors / data.data (the embedded block).
test_shared_vectors if {
	vectors := data.vectors
	bundle_data := data.data
	every v in vectors {
		got := authz.allow with input as v.input
			with data.rbac as bundle_data.rbac
			with data.abac as bundle_data.abac
			with data.sod as bundle_data.sod
		got == v.want_allow
	}
}
