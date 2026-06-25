package lifecycle

import (
	"reflect"
	"testing"

	"github.com/lifecycle/control-plane/internal/domain"
)

func ids(es []domain.Entitlement) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.ID
	}
	return out
}

func TestComputeMoverDiff(t *testing.T) {
	cur := []domain.Entitlement{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	tgt := []domain.Entitlement{{ID: "b"}, {ID: "c"}, {ID: "d"}}
	diff := ComputeMoverDiff(cur, tgt)
	if want := []string{"d"}; !reflect.DeepEqual(ids(diff.Grant), want) {
		t.Fatalf("Grant ids = %v, want %v", ids(diff.Grant), want)
	}
	if want := []string{"a"}; !reflect.DeepEqual(ids(diff.Revoke), want) {
		t.Fatalf("Revoke ids = %v, want %v", ids(diff.Revoke), want)
	}
}

// Guards the recalculate-don't-accumulate rule: a Mover that only ever grants
// (never revokes entitlements dropped from target) is a bug.
func TestMoverIsNotAddOnly(t *testing.T) {
	cur := []domain.Entitlement{{ID: "old-team-admin"}}
	tgt := []domain.Entitlement{{ID: "new-team-member"}}
	diff := ComputeMoverDiff(cur, tgt)
	if len(diff.Revoke) == 0 {
		t.Fatal("add-only Mover bug: dropped entitlement was not revoked")
	}
	if diff.Revoke[0].ID != "old-team-admin" {
		t.Fatalf("Revoke = %v, want old-team-admin", ids(diff.Revoke))
	}
}

func TestMoverDiffDeterministic(t *testing.T) {
	cur := []domain.Entitlement{{ID: "z"}, {ID: "a"}}
	diff := ComputeMoverDiff(cur, nil)
	if want := []string{"a", "z"}; !reflect.DeepEqual(ids(diff.Revoke), want) {
		t.Fatalf("Revoke not sorted: %v", ids(diff.Revoke))
	}
}
