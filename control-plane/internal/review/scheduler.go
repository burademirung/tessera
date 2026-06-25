// Package review schedules risk-tiered access reviews and builds distributed
// micro-certification batches with reviewer != grantor enforcement and
// last-use-driven revoke recommendations (research 02 §3).
package review

import (
	"fmt"
	"time"

	"github.com/tessera/control-plane/internal/domain"
)

// CadencePolicy maps a risk tier to its review interval (the D1 policy table).
type CadencePolicy struct {
	Tier     domain.RiskTier
	Interval time.Duration
}

// DueForReview reports whether an identity at a given tier is due, per cadence.
// An unknown or undefined tier is treated as due (fail closed): the identity
// must be reviewed rather than silently skipped.
func DueForReview(_ domain.Identity, tier domain.RiskTier, lastReviewed time.Time, policy []CadencePolicy, now time.Time) bool {
	for _, p := range policy {
		if p.Tier == tier {
			return now.Sub(lastReviewed) >= p.Interval
		}
	}
	// Unknown tier: fail closed — treat as due for review.
	return true
}

// ReviewItem is one entitlement to certify, pre-populated with a recommendation.
type ReviewItem struct {
	IdentityID     string
	EntitlementID  string
	Reviewer       string
	Recommendation string // "keep" | "revoke"
	LastUsed       *time.Time
}

// BuildItems produces one certification item per entitlement. It enforces
// reviewer != grantor and pre-populates a "revoke" recommendation for unused
// or stale entitlements.
func BuildItems(i domain.Identity, reviewerFor func(domain.Entitlement) string, now time.Time, staleAfter time.Duration) ([]ReviewItem, error) {
	var items []ReviewItem
	for _, e := range i.Entitlements {
		reviewer := reviewerFor(e)
		// Fail closed: an empty/unresolved reviewer means no one is assigned —
		// the entitlement would never be certified.  Reject it explicitly.
		if reviewer == "" {
			return nil, fmt.Errorf("reviewer is unresolved (empty) for entitlement %s (fail closed)", e.ID)
		}
		// Separation of Duties: reviewer must differ from the grantor.
		if reviewer == e.GrantedBy {
			return nil, fmt.Errorf("reviewer %q equals grantor for entitlement %s (reviewer must differ from grantor)", reviewer, e.ID)
		}
		// Least privilege: default to revoke; keeping requires the entitlement
		// to have been used more recently than the stale threshold.
		// Use >= so that "exactly at the boundary" is also treated as stale.
		rec := "revoke"
		if e.LastUsed != nil && now.Sub(*e.LastUsed) < staleAfter {
			rec = "keep"
		}
		items = append(items, ReviewItem{
			IdentityID:     i.ID,
			EntitlementID:  e.ID,
			Reviewer:       reviewer,
			Recommendation: rec,
			LastUsed:       e.LastUsed,
		})
	}
	return items, nil
}

// Batch groups items into small per-reviewer batches (micro-certification).
func Batch(items []ReviewItem, perReviewer int) map[string][][]ReviewItem {
	if perReviewer < 1 {
		perReviewer = 1
	}
	byReviewer := map[string][]ReviewItem{}
	for _, it := range items {
		byReviewer[it.Reviewer] = append(byReviewer[it.Reviewer], it)
	}
	out := map[string][][]ReviewItem{}
	for reviewer, rs := range byReviewer {
		for start := 0; start < len(rs); start += perReviewer {
			end := start + perReviewer
			if end > len(rs) {
				end = len(rs)
			}
			// Copy the slice to avoid shared backing array across batches.
			// Without this, appending to one batch's sub-slice can silently
			// overwrite items in the next batch (state drift).
			batch := make([]ReviewItem, end-start)
			copy(batch, rs[start:end])
			out[reviewer] = append(out[reviewer], batch)
		}
	}
	return out
}
