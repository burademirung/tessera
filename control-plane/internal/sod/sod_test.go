package sod

import (
	"context"
	"testing"

	"github.com/tessera/control-plane/internal/domain"
)

type fakePE struct {
	violationsFor map[string][]SoDViolation
}

func (f *fakePE) EvalSoD(_ context.Context, in SoDInput) (SoDDecision, error) {
	return SoDDecision{Violations: f.violationsFor[in.IdentityID]}, nil
}

func TestDetectiveSweep(t *testing.T) {
	pe := &fakePE{violationsFor: map[string][]SoDViolation{
		"u1": {{A: "create-payment", B: "approve-payment", Rule: "sod-payments"}},
	}}
	ids := []domain.Identity{
		{ID: "u1", Entitlements: []domain.Entitlement{{ID: "create-payment"}, {ID: "approve-payment"}}},
		{ID: "u2", Entitlements: []domain.Entitlement{{ID: "read-only"}}},
		{ID: "u3"}, // no entitlements -> skipped
	}
	got, err := DetectiveSweep(context.Background(), pe, ids)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(got["u1"]) != 1 || got["u1"][0].Rule != "sod-payments" {
		t.Fatalf("u1 violations = %#v", got["u1"])
	}
	if _, ok := got["u2"]; ok {
		t.Fatalf("u2 has no violations and must be absent")
	}
	if _, ok := got["u3"]; ok {
		t.Fatalf("u3 has no entitlements and must be skipped")
	}
}
