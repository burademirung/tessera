package domain

import "testing"

func TestCanTransition(t *testing.T) {
	tests := []struct {
		from, to LifecycleState
		want     bool
	}{
		{StateInvited, StateProvisioned, true},
		{StateProvisioned, StateActive, true},
		{StateActive, StateReviewDue, true},
		{StateReviewDue, StateActive, true},
		{StateActive, StateOffboarded, true},
		{StateReviewDue, StateOffboarded, true},
		{StateProvisioned, StateOffboarded, true},
		{StateInvited, StateActive, false},    // must be provisioned first
		{StateOffboarded, StateActive, false}, // terminal
		{StateActive, StateInvited, false},    // no going back
		{StateActive, "frozen", false},        // unknown target
	}
	for _, tt := range tests {
		t.Run(string(tt.from)+"->"+string(tt.to), func(t *testing.T) {
			if got := CanTransition(tt.from, tt.to); got != tt.want {
				t.Fatalf("CanTransition(%q,%q) = %v, want %v", tt.from, tt.to, got, tt.want)
			}
		})
	}
}

func TestTransitionMutatesOrErrors(t *testing.T) {
	i := &Identity{ID: "u1", Type: IdentityHuman, State: StateInvited}
	if err := i.Transition(StateProvisioned); err != nil {
		t.Fatalf("legal transition errored: %v", err)
	}
	if i.State != StateProvisioned {
		t.Fatalf("state = %q, want provisioned", i.State)
	}
	if err := i.Transition(StateInvited); err == nil {
		t.Fatalf("illegal transition should error")
	}
	if i.State != StateProvisioned {
		t.Fatalf("illegal transition must not mutate state, got %q", i.State)
	}
}
