// Package scim reconciles control-plane identity state with the edge SCIM
// service provider. It never hard-deletes; extras are disabled (active=false).
package scim

import (
	"context"
	"fmt"

	"github.com/lifecycle/control-plane/internal/domain"
	"github.com/lifecycle/control-plane/internal/ports"
)

// ReconcileResult is the diff between desired and observed SCIM state.
type ReconcileResult struct {
	ToCreate  []domain.Identity
	ToUpdate  []domain.Identity
	ToDisable []string
}

// Plan computes the reconciliation actions. desired is the control-plane
// source of truth; observed is the edge SCIM endpoint's current users.
func Plan(desired, observed []domain.Identity) ReconcileResult {
	obs := index(observed)
	des := index(desired)
	var r ReconcileResult
	for id, d := range des {
		o, ok := obs[id]
		switch {
		case !ok:
			r.ToCreate = append(r.ToCreate, d)
		case o.Email != d.Email || o.Type != d.Type:
			r.ToUpdate = append(r.ToUpdate, d)
		}
	}
	for id := range obs {
		if _, want := des[id]; !want {
			r.ToDisable = append(r.ToDisable, id)
		}
	}
	return r
}

// Apply pushes the planned changes to the SCIM client.
func Apply(ctx context.Context, c ports.SCIMClient, r ReconcileResult) error {
	for _, u := range r.ToCreate {
		if err := c.PushUser(ctx, u); err != nil {
			return fmt.Errorf("scim create %s: %w", u.ID, err)
		}
	}
	for _, u := range r.ToUpdate {
		if err := c.PushUser(ctx, u); err != nil {
			return fmt.Errorf("scim update %s: %w", u.ID, err)
		}
	}
	for _, id := range r.ToDisable {
		if err := c.SetActive(ctx, id, false); err != nil {
			return fmt.Errorf("scim disable %s: %w", id, err)
		}
	}
	return nil
}

func index(ids []domain.Identity) map[string]domain.Identity {
	m := make(map[string]domain.Identity, len(ids))
	for _, i := range ids {
		m[i.ID] = i
	}
	return m
}
