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

// Security Issue 1: Fail-Open on Unknown Risk Tier in DueForReview.
// An identity with an unknown/undefined tier must be treated as due for review
// (fail closed), not silently skipped (fail open).
func TestDueForReview_UnknownTierFailsClosed(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	lastReviewed := now.Add(-400 * 24 * time.Hour) // very stale
	unknownTier := domain.RiskTier("super-secret-unknown")
	// With an unknown tier the current code returns false (not due) — fail open.
	// Security requirement: unknown tier must be treated as due (fail closed).
	if !DueForReview(domain.Identity{}, unknownTier, lastReviewed, policy, now) {
		t.Fatal("unknown risk tier must be treated as due for review (fail closed), got not-due")
	}
}

// Security Issue 2: Fail-Open on Empty Reviewer in BuildItems (SoD gap).
// If reviewerFor returns "" (empty / unresolved reviewer) and GrantedBy is
// non-empty, the SoD check passes and a ReviewItem is emitted with no reviewer —
// the entitlement is never reviewed. Must error instead.
func TestBuildItems_EmptyReviewerRejected(t *testing.T) {
	now := time.Now()
	id := domain.Identity{
		ID: "u1",
		Entitlements: []domain.Entitlement{
			{ID: "e1", GrantedBy: "mgr"},
		},
	}
	// reviewerFor returns "" — nobody is assigned
	_, err := BuildItems(id, func(domain.Entitlement) string { return "" }, now, time.Hour)
	if err == nil {
		t.Fatal("empty reviewer (unresolved) must be rejected with an error (fail closed), got nil")
	}
}

// Security Issue 3: Least-Privilege default — fresh entitlement with LastUsed
// exactly at the stale boundary must default to "revoke", not "keep".
// The current check uses strictly-greater-than (>), so an entitlement used
// exactly staleAfter ago passes as "keep" instead of "revoke".
func TestBuildItems_StaleAtBoundaryDefaultsToRevoke(t *testing.T) {
	staleAfter := 90 * 24 * time.Hour
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	atBoundary := now.Add(-staleAfter) // exactly staleAfter ago
	id := domain.Identity{
		ID: "u1",
		Entitlements: []domain.Entitlement{
			{ID: "e1", GrantedBy: "mgr", LastUsed: &atBoundary},
		},
	}
	items, err := BuildItems(id, func(domain.Entitlement) string { return "reviewer" }, now, staleAfter)
	if err != nil {
		t.Fatalf("BuildItems: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	if items[0].Recommendation != "revoke" {
		t.Fatalf("entitlement last used exactly staleAfter ago should be 'revoke' (least privilege), got %q", items[0].Recommendation)
	}
}

// Security Issue 4: State Drift — Batch returns sub-slices that share the
// backing array of the internal per-reviewer slice. Appending to one batch's
// sub-slice can silently overwrite items in an adjacent batch because the
// sub-slices have capacity beyond their length (state drift).
func TestBatch_NoBatchSharedBackingArray(t *testing.T) {
	// 3 items for r1 with batch size 2 → batch[0] has len=2 but cap may be 3
	// so that appending to batch[0] overwrites batch[1][0] in the backing array.
	items := []ReviewItem{
		{Reviewer: "r1", EntitlementID: "e0"},
		{Reviewer: "r1", EntitlementID: "e1"},
		{Reviewer: "r1", EntitlementID: "e2"},
	}
	b := Batch(items, 2)
	batches := b["r1"]
	if len(batches) != 2 {
		t.Fatalf("want 2 batches for r1, got %d", len(batches))
	}
	originalSecondItem := batches[1][0].EntitlementID
	// Append a new item to the first batch; if they share backing array capacity
	// the appended element lands at index 2 of the backing array — exactly where
	// batch[1][0] lives — and the next read of batch[1][0] would show the wrong value.
	_ = append(batches[0], ReviewItem{EntitlementID: "INJECTED"})
	// batch[1][0] must be unchanged after the append.
	if batches[1][0].EntitlementID != originalSecondItem {
		t.Fatalf("state drift: appending to batch[0] mutated batch[1][0] from %q to %q (shared backing array)",
			originalSecondItem, batches[1][0].EntitlementID)
	}
}
