package iac_test

import data.iac

test_bad_plan_has_violations if {
	msgs := iac.deny with input as data.plan_bad
	count(msgs) >= 2
}

test_good_plan_is_clean if {
	msgs := iac.deny with input as data.plan_good
	count(msgs) == 0
}

test_wildcard_sub_is_flagged if {
	msgs := iac.deny with input as data.plan_bad
	some m in msgs
	contains(m, "StringLike")
}
