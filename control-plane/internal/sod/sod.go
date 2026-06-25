// Package sod runs detective separation-of-duties sweeps by delegating to the
// policy engine (OPA/Regorus). The control plane (PA) never embeds the SoD
// matrix; it only calls the PE and acts on the decision.
package sod

import (
	"context"
	"fmt"

	"github.com/lifecycle/control-plane/internal/domain"
)

// PolicyEngine is the seam to the SoD-evaluating policy engine.
type PolicyEngine interface {
	EvalSoD(ctx context.Context, input SoDInput) (SoDDecision, error)
}

// SoDInput is the entitlement set evaluated for one identity.
type SoDInput struct {
	IdentityID     string
	EntitlementIDs []string
}

// SoDViolation is a toxic entitlement pair flagged by the policy.
type SoDViolation struct {
	A    string
	B    string
	Rule string
}

// SoDDecision is the policy engine's verdict.
type SoDDecision struct {
	Violations []SoDViolation
}

// DetectiveSweep evaluates SoD across identities, returning violations keyed by
// identity id (only identities that have violations appear in the map).
func DetectiveSweep(ctx context.Context, pe PolicyEngine, ids []domain.Identity) (map[string][]SoDViolation, error) {
	out := make(map[string][]SoDViolation)
	for _, id := range ids {
		if len(id.Entitlements) == 0 {
			continue
		}
		entIDs := make([]string, len(id.Entitlements))
		for i, e := range id.Entitlements {
			entIDs[i] = e.ID
		}
		dec, err := pe.EvalSoD(ctx, SoDInput{IdentityID: id.ID, EntitlementIDs: entIDs})
		if err != nil {
			return nil, fmt.Errorf("sod eval %s: %w", id.ID, err)
		}
		if len(dec.Violations) > 0 {
			out[id.ID] = dec.Violations
		}
	}
	return out, nil
}
