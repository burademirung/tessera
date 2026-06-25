package lifecycle

import (
	"testing"
	"time"

	"github.com/lifecycle/control-plane/internal/domain"
)

func TestComputeJoinerGrants(t *testing.T) {
	policies := []BirthrightPolicy{
		{Department: "eng", Entitlements: []domain.Entitlement{{ID: "repo-read", Role: "developer"}}},
		{Department: "sales", Entitlements: []domain.Entitlement{{ID: "crm", Role: "rep"}}},
	}
	got := ComputeJoinerGrants("eng", policies)
	if len(got) != 1 || got[0].ID != "repo-read" {
		t.Fatalf("ComputeJoinerGrants(eng) = %#v", got)
	}
	if none := ComputeJoinerGrants("legal", policies); len(none) != 0 {
		t.Fatalf("unknown department should grant nothing, got %#v", none)
	}
}

func TestApplyJIT(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	priv := domain.Entitlement{ID: "prod-admin", Privileged: true}
	t.Run("approved privileged is time-boxed", func(t *testing.T) {
		ent, exp, err := ApplyJIT(JITGrant{Entitlement: priv, TTL: 2 * time.Hour, Approved: true}, now)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !exp.Equal(now.Add(2 * time.Hour)) {
			t.Fatalf("expiry = %v, want %v", exp, now.Add(2*time.Hour))
		}
		if !ent.Privileged {
			t.Fatalf("entitlement should stay privileged")
		}
	})
	t.Run("unapproved rejected", func(t *testing.T) {
		if _, _, err := ApplyJIT(JITGrant{Entitlement: priv, TTL: time.Hour, Approved: false}, now); err == nil {
			t.Fatal("unapproved JIT must error")
		}
	})
	t.Run("non-privileged rejected", func(t *testing.T) {
		std := domain.Entitlement{ID: "repo-read"}
		if _, _, err := ApplyJIT(JITGrant{Entitlement: std, TTL: time.Hour, Approved: true}, now); err == nil {
			t.Fatal("JIT is privileged-only; must error")
		}
	})
	t.Run("non-positive TTL rejected", func(t *testing.T) {
		if _, _, err := ApplyJIT(JITGrant{Entitlement: priv, TTL: 0, Approved: true}, now); err == nil {
			t.Fatal("zero TTL must error")
		}
	})
}
