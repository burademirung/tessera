package lifecycle

import (
	"sort"

	"github.com/tessera/control-plane/internal/domain"
)

// MoverDiff is the recalculated set difference for a role change.
type MoverDiff struct {
	Grant  []domain.Entitlement
	Revoke []domain.Entitlement
}

// ComputeMoverDiff recalculates entitlements from scratch:
//
//	Grant  = target - current
//	Revoke = current - target
//
// This is the recalculate-don't-accumulate rule. An add-only Mover (one that
// never revokes) is a bug; Revoke is always populated for dropped entitlements.
func ComputeMoverDiff(current, target []domain.Entitlement) MoverDiff {
	curByID := index(current)
	tgtByID := index(target)

	var diff MoverDiff
	for id, e := range tgtByID {
		if _, held := curByID[id]; !held {
			diff.Grant = append(diff.Grant, e)
		}
	}
	for id, e := range curByID {
		if _, want := tgtByID[id]; !want {
			diff.Revoke = append(diff.Revoke, e)
		}
	}
	sortByID(diff.Grant)
	sortByID(diff.Revoke)
	return diff
}

func index(es []domain.Entitlement) map[string]domain.Entitlement {
	m := make(map[string]domain.Entitlement, len(es))
	for _, e := range es {
		m[e.ID] = e
	}
	return m
}

func sortByID(es []domain.Entitlement) {
	sort.Slice(es, func(i, j int) bool { return es[i].ID < es[j].ID })
}
