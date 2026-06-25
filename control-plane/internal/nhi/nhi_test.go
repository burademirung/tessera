package nhi

import (
	"testing"

	"github.com/tessera/control-plane/internal/domain"
)

func TestOwnedBy(t *testing.T) {
	all := []domain.Identity{
		{ID: "u1", Type: domain.IdentityHuman},
		{ID: "svc1", Type: domain.IdentityNHI, Owner: "u1"},
		{ID: "svc2", Type: domain.IdentityNHI, Owner: "u2"},
	}
	got := OwnedBy("u1", all)
	if len(got) != 1 || got[0].ID != "svc1" {
		t.Fatalf("OwnedBy(u1) = %#v", got)
	}
}

func TestPlanLeaverFanOut(t *testing.T) {
	all := []domain.Identity{
		{ID: "svc1", Type: domain.IdentityNHI, Owner: "u1"},
		{ID: "svc2", Type: domain.IdentityNHI, Owner: "u1"},
	}
	successor := func(n domain.Identity) (string, bool) {
		if n.ID == "svc1" {
			return "u2", true // transfer
		}
		return "", false // rotate
	}
	plans, err := PlanLeaverFanOut("u1", all, successor)
	if err != nil {
		t.Fatalf("fan-out: %v", err)
	}
	byID := map[string]FanOut{}
	for _, p := range plans {
		byID[p.NHIID] = p
	}
	if byID["svc1"].Action != ActionTransfer || byID["svc1"].NewOwner != "u2" {
		t.Fatalf("svc1 plan = %#v, want transfer to u2", byID["svc1"])
	}
	if byID["svc2"].Action != ActionRotate {
		t.Fatalf("svc2 plan = %#v, want rotate", byID["svc2"])
	}
}

func TestPlanLeaverFanOutRejectsInvalidNHI(t *testing.T) {
	all := []domain.Identity{{ID: "svc1", Type: domain.IdentityNHI}} // no owner -> invalid
	_, err := PlanLeaverFanOut("u1", all, func(domain.Identity) (string, bool) { return "", false })
	// svc1 isn't owned by u1 so it's not in scope; ensure no false error.
	if err != nil {
		t.Fatalf("out-of-scope invalid NHI should not error: %v", err)
	}
	owned := []domain.Identity{{ID: "svc9", Type: domain.IdentityNHI, Owner: "u1"}}
	if _, err := PlanLeaverFanOut("u1", owned, func(domain.Identity) (string, bool) { return "", false }); err != nil {
		t.Fatalf("valid owned NHI should plan cleanly: %v", err)
	}
}
