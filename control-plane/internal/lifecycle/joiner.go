// Package lifecycle implements the Joiner/Mover/Leaver business logic.
package lifecycle

import (
	"fmt"
	"time"

	"github.com/tessera/control-plane/internal/domain"
)

// BirthrightPolicy maps a department to its day-one (non-privileged) grants.
type BirthrightPolicy struct {
	Department   string
	Entitlements []domain.Entitlement
}

// JITGrant is a requested just-in-time, time-boxed privileged grant.
type JITGrant struct {
	Entitlement domain.Entitlement
	TTL         time.Duration
	Approved    bool
}

// ComputeJoinerGrants returns the birthright entitlements for a department.
func ComputeJoinerGrants(department string, policies []BirthrightPolicy) []domain.Entitlement {
	var out []domain.Entitlement
	for _, p := range policies {
		if p.Department == department {
			out = append(out, p.Entitlements...)
		}
	}
	return out
}

// ApplyJIT validates and time-boxes a privileged JIT grant, returning the
// entitlement and its hard expiry. Privileged access is never standing.
func ApplyJIT(g JITGrant, now time.Time) (domain.Entitlement, time.Time, error) {
	if !g.Approved {
		return domain.Entitlement{}, time.Time{}, fmt.Errorf("jit grant %s not approved", g.Entitlement.ID)
	}
	if !g.Entitlement.Privileged {
		return domain.Entitlement{}, time.Time{}, fmt.Errorf("jit grant %s is not privileged; jit is privileged-only", g.Entitlement.ID)
	}
	if g.TTL <= 0 {
		return domain.Entitlement{}, time.Time{}, fmt.Errorf("jit grant %s requires positive TTL", g.Entitlement.ID)
	}
	return g.Entitlement, now.Add(g.TTL), nil
}
