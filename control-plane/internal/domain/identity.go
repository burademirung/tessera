// Package domain holds the pure identity/entitlement model and JML state machine.
package domain

import (
	"fmt"
	"time"
)

// IdentityType separates human principals from non-human identities (NHIs).
type IdentityType string

const (
	IdentityHuman IdentityType = "human"
	IdentityNHI   IdentityType = "nhi"
)

// RiskTier drives access-review cadence (research 02 §3).
type RiskTier string

const (
	RiskPrivileged RiskTier = "privileged"
	RiskStandard   RiskTier = "standard"
	RiskLow        RiskTier = "low"
)

// LifecycleState is the JML state; transitions live in lifecycle.go (Task 3).
type LifecycleState string

// Entitlement is one role/resource grant held by an identity.
type Entitlement struct {
	ID         string
	Role       string
	Resource   string
	Privileged bool
	GrantedBy  string // grantor identity id; reviewer must differ from this
	GrantedAt  time.Time
	LastUsed   *time.Time // nil = never used; drives revoke recommendations
}

// Identity is a human or NHI with its current entitlement set.
type Identity struct {
	ID           string
	Email        string
	Type         IdentityType
	Owner        string // REQUIRED for NHI, MUST be empty for human
	State        LifecycleState
	Entitlements []Entitlement
	ManagerID    string
}

// Validate enforces the type/owner invariants.
func (i Identity) Validate() error {
	switch i.Type {
	case IdentityHuman:
		if i.Owner != "" {
			return fmt.Errorf("human identity %s must not have an owner", i.ID)
		}
	case IdentityNHI:
		if i.Owner == "" {
			return fmt.Errorf("nhi identity %s must have a human owner", i.ID)
		}
	default:
		return fmt.Errorf("identity %s has unknown type %q", i.ID, i.Type)
	}
	return nil
}

// EntitlementIDs indexes the entitlements by id.
func (i Identity) EntitlementIDs() map[string]Entitlement {
	m := make(map[string]Entitlement, len(i.Entitlements))
	for _, e := range i.Entitlements {
		m[e.ID] = e
	}
	return m
}
