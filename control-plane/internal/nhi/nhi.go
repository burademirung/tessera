// Package nhi handles non-human-identity lifecycle. Every NHI has a mandatory
// human owner; when that human leaves, ownership of each NHI is transferred to
// a successor or, lacking one, its credentials are rotated and flagged.
package nhi

import (
	"fmt"

	"github.com/tessera/control-plane/internal/domain"
)

// Action is the disposition for an owned NHI on a human leaver.
type Action string

const (
	ActionTransfer Action = "transfer"
	ActionRotate   Action = "rotate"
)

// FanOut is the planned action for one NHI.
type FanOut struct {
	NHIID    string
	Action   Action
	NewOwner string // set only for transfer
}

// OwnedBy returns the NHIs owned by the given human.
func OwnedBy(owner string, all []domain.Identity) []domain.Identity {
	var out []domain.Identity
	for _, i := range all {
		if i.Type == domain.IdentityNHI && i.Owner == owner {
			out = append(out, i)
		}
	}
	return out
}

// PlanLeaverFanOut computes transfer-or-rotate actions for every NHI the leaver
// owns. successor returns (newOwner, true) to transfer, or ("", false) to rotate.
func PlanLeaverFanOut(leaver string, all []domain.Identity, successor func(nhi domain.Identity) (string, bool)) ([]FanOut, error) {
	var plans []FanOut
	for _, n := range OwnedBy(leaver, all) {
		if err := n.Validate(); err != nil {
			return nil, fmt.Errorf("owned nhi invariant breach: %w", err)
		}
		if newOwner, ok := successor(n); ok {
			plans = append(plans, FanOut{NHIID: n.ID, Action: ActionTransfer, NewOwner: newOwner})
		} else {
			plans = append(plans, FanOut{NHIID: n.ID, Action: ActionRotate})
		}
	}
	return plans, nil
}
