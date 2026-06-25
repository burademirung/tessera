package domain

import "fmt"

const (
	StateInvited     LifecycleState = "invited"
	StateProvisioned LifecycleState = "provisioned"
	StateActive      LifecycleState = "active"
	StateReviewDue   LifecycleState = "review-due"
	StateOffboarded  LifecycleState = "offboarded"
)

// transitions is the adjacency set of legal JML moves. offboarded is terminal.
var transitions = map[LifecycleState]map[LifecycleState]bool{
	StateInvited:     {StateProvisioned: true},
	StateProvisioned: {StateActive: true, StateOffboarded: true},
	StateActive:      {StateReviewDue: true, StateOffboarded: true},
	StateReviewDue:   {StateActive: true, StateOffboarded: true},
	StateOffboarded:  {},
}

// CanTransition reports whether from->to is a legal JML move.
func CanTransition(from, to LifecycleState) bool {
	return transitions[from][to]
}

// Transition advances the identity's state or returns an error, leaving state
// unchanged on an illegal move.
func (i *Identity) Transition(to LifecycleState) error {
	if !CanTransition(i.State, to) {
		return fmt.Errorf("illegal lifecycle transition %q -> %q for %s", i.State, to, i.ID)
	}
	i.State = to
	return nil
}
