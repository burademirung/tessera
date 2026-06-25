package review

import (
	"testing"
	"time"

	"github.com/lifecycle/control-plane/internal/domain"
)

var policy = []CadencePolicy{
	{Tier: domain.RiskPrivileged, Interval: 30 * 24 * time.Hour},
	{Tier: domain.RiskStandard, Interval: 90 * 24 * time.Hour},
	{Tier: domain.RiskLow, Interval: 365 * 24 * time.Hour},
}

func TestDueForReview(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	priv := now.Add(-31 * 24 * time.Hour)
	if !DueForReview(domain.Identity{}, domain.RiskPrivileged, priv, policy, now) {
		t.Fatal("privileged reviewed 31d ago should be due (30d cadence)")
	}
	recent := now.Add(-10 * 24 * time.Hour)
	if DueForReview(domain.Identity{}, domain.RiskStandard, recent, policy, now) {
		t.Fatal("standard reviewed 10d ago should NOT be due (90d cadence)")
	}
}

func TestBuildItemsReviewerNotGrantor(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	old := now.Add(-200 * 24 * time.Hour)
	id := domain.Identity{
		ID: "u1",
		Entitlements: []domain.Entitlement{
			{ID: "e1", GrantedBy: "mgr", LastUsed: &old}, // stale -> revoke rec
			{ID: "e2", GrantedBy: "mgr", LastUsed: nil},  // never used -> revoke rec
		},
	}
	items, err := BuildItems(id, func(domain.Entitlement) string { return "reviewer" }, now, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("BuildItems: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	for _, it := range items {
		if it.Reviewer == "mgr" {
			t.Fatal("reviewer must not equal grantor")
		}
		if it.Recommendation != "revoke" {
			t.Fatalf("stale/unused entitlement should pre-populate revoke, got %q", it.Recommendation)
		}
	}
}

func TestBuildItemsRejectsGrantorAsReviewer(t *testing.T) {
	now := time.Now()
	id := domain.Identity{ID: "u1", Entitlements: []domain.Entitlement{{ID: "e1", GrantedBy: "mgr"}}}
	_, err := BuildItems(id, func(domain.Entitlement) string { return "mgr" }, now, time.Hour)
	if err == nil {
		t.Fatal("assigning the grantor as reviewer must error")
	}
}

func TestBatch(t *testing.T) {
	items := []ReviewItem{
		{Reviewer: "r1"}, {Reviewer: "r1"}, {Reviewer: "r1"},
		{Reviewer: "r2"},
	}
	b := Batch(items, 2)
	if len(b["r1"]) != 2 { // 3 items / batch size 2 -> 2 batches
		t.Fatalf("r1 batches = %d, want 2", len(b["r1"]))
	}
	if len(b["r2"]) != 1 {
		t.Fatalf("r2 batches = %d, want 1", len(b["r2"]))
	}
}
