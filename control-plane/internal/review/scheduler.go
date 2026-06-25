// Package review schedules risk-tiered access reviews and builds distributed
// micro-certification batches with reviewer != grantor enforcement and
// last-use-driven revoke recommendations (research 02 §3).
package review

import (
	"fmt"
	"time"

	"github.com/lifecycle/control-plane/internal/domain"
)

// CadencePolicy maps a risk tier to its review interval (the D1 policy table).
type CadencePolicy struct {
	Tier     domain.RiskTier
	Interval time.Duration
}

// DueForReview reports whether an identity at a given tier is due, per cadence.
func DueForReview(_ domain.Identity, tier domain.RiskTier, lastReviewed time.Time, policy []CadencePolicy, now time.Time) bool {
	for _, p := range policy {
		if p.Tier == tier {
			return now.Sub(lastReviewed) >= p.Interval
		}
	}
	return false
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
		if reviewer == e.GrantedBy {
			return nil, fmt.Errorf("reviewer %q equals grantor for entitlement %s (reviewer must differ from grantor)", reviewer, e.ID)
		}
		rec := "keep"
		if e.LastUsed == nil || now.Sub(*e.LastUsed) > staleAfter {
			rec = "revoke"
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
			out[reviewer] = append(out[reviewer], rs[start:end])
		}
	}
	return out
}
