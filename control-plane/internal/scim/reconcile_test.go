package scim

import (
	"context"
	"testing"

	"github.com/tessera/control-plane/internal/domain"
)

type fakeSCIM struct {
	pushed   []domain.Identity
	disabled []string
}

func (f *fakeSCIM) PushUser(_ context.Context, u domain.Identity) error {
	f.pushed = append(f.pushed, u)
	return nil
}
func (f *fakeSCIM) SetActive(_ context.Context, id string, active bool) error {
	if !active {
		f.disabled = append(f.disabled, id)
	}
	return nil
}
func (f *fakeSCIM) ListUsers(_ context.Context) ([]domain.Identity, error) { return nil, nil }

func TestPlan(t *testing.T) {
	desired := []domain.Identity{
		{ID: "u1", Email: "a@x", Type: domain.IdentityHuman},
		{ID: "u2", Email: "b@x", Type: domain.IdentityHuman},
	}
	observed := []domain.Identity{
		{ID: "u2", Email: "old@x", Type: domain.IdentityHuman}, // drifted
		{ID: "u3", Email: "c@x", Type: domain.IdentityHuman},   // extra -> disable
	}
	r := Plan(desired, observed)
	if len(r.ToCreate) != 1 || r.ToCreate[0].ID != "u1" {
		t.Fatalf("ToCreate = %#v", r.ToCreate)
	}
	if len(r.ToUpdate) != 1 || r.ToUpdate[0].ID != "u2" {
		t.Fatalf("ToUpdate = %#v", r.ToUpdate)
	}
	if len(r.ToDisable) != 1 || r.ToDisable[0] != "u3" {
		t.Fatalf("ToDisable = %#v (must disable, never hard-delete)", r.ToDisable)
	}
}

func TestApply(t *testing.T) {
	f := &fakeSCIM{}
	r := ReconcileResult{
		ToCreate:  []domain.Identity{{ID: "u1"}},
		ToUpdate:  []domain.Identity{{ID: "u2"}},
		ToDisable: []string{"u3"},
	}
	if err := Apply(context.Background(), f, r); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(f.pushed) != 2 {
		t.Fatalf("pushed = %d, want 2 (create+update)", len(f.pushed))
	}
	if len(f.disabled) != 1 || f.disabled[0] != "u3" {
		t.Fatalf("disabled = %#v", f.disabled)
	}
}
