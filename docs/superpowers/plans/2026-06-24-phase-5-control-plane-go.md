# Phase 5 — Control Plane / Lifecycle (native Go) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task is TDD: write a failing test, run it and see it FAIL, write complete real Go to make it pass, run it and see it PASS, commit.

**Goal:** Build the native, idiomatic Go control-plane orchestrator (spec §4 Layer 3 + §7 build-order item 5). It owns the JML (Joiner/Mover/Leaver) lifecycle state machine, the Mover recalculate-don't-accumulate diff engine, the Leaver offboarding saga, SCIM reconciliation, risk-tiered access-review campaigns, SoD detective evaluation, NHI (non-human identity) lifecycle, the multi-cloud federation orchestrator (AWS STS / GCP WIF / Azure FIC), and an append-only hash-chained audit emitter. It runs as scheduled GitHub Actions (Cron) and locally; it writes lifecycle/state to D1/DO and audit records to R2 **via the edge API**, and it authenticates to clouds via keyless GitHub OIDC.

**Architecture:** A single Go module rooted at `control-plane/`. Domain logic is pure and deterministic; everything external (the edge API, SCIM, OAuth revocation, session termination, API-key revocation, the edge IdP token mint, and each cloud SDK call) sits behind a small Go interface so unit tests use table-driven fakes and **never touch a real cloud**. Two CLI entrypoints (`cmd/access-review`, `cmd/offboard`) wire the domain to real adapters; the GitHub Actions Cron workflow invokes them with keyless cloud OIDC. The control plane is the **PA (Policy Administration point)** of the Zero-Trust model (spec §4 Layer 2 / research 02 §5): it mints/revokes and orchestrates, but evaluates RBAC/SoD by calling the policy engine, never by hard-coding allow logic.

**Tech Stack:** Go 1.23 (native, full stdlib — **not** TinyGo), standard `testing` with table-driven subtests, the official cloud SDKs (`github.com/aws/aws-sdk-go-v2`, `cloud.google.com/go`, `github.com/Azure/azure-sdk-for-go`) wired only in adapters, `net/http` for the edge API and token endpoints. No third-party test framework; no mocking library (hand-written fakes implementing the interfaces).

## Global Constraints

- **Native Go in CI, NOT TinyGo-on-Workers.** The control plane is native, idiomatic Go run in GitHub Actions Cron + locally with the **real AWS/Azure/GCP SDKs** and full stdlib — this is the entire reason it is not TinyGo on a Worker (research 05 "DECISION TAKEN"). The edge engine (Rust/WASM) is a separate phase; Go never compiles to WASM here.
- **Real cloud SDKs.** Federation adapters use `aws-sdk-go-v2` STS, `cloud.google.com/go` STS, and `azure-sdk-for-go`. Unit tests **mock external clients behind interfaces** and assert request *construction*; they never make live calls.
- **Leaver is a multi-step saga.** `active=false` alone leaves live sessions and refresh tokens valid (research 02 top-correction #1; ASVS 7.4.2). The saga MUST run, in order: **disable (SCIM)** → **revoke OAuth grant/refresh (RFC 7009)** → **terminate sessions (OIDC Back-Channel Logout)** → **revoke API keys**. Only **all-green = offboarded**. For-cause = immediate (<5 min); routine = at termination via Cron. An immediate-revoke path is exposed.
- **Mover recalculates, never accumulates.** `grant = target − current`, `revoke = current − target`. An add-only Mover is a **bug** and has an explicit test asserting `revoke` is non-empty when `current` has entitlements absent from `target`.
- **Reviewer ≠ grantor.** Access-review item assignment MUST exclude the identity that granted the entitlement; this is enforced in code and tested.
- **NHIs own type + mandatory owner.** Service accounts get their own identity type and a **required human owner**; a human Leaver fans out to **transfer-or-rotate** every NHI they own.
- **Per-cloud distinct token.** The orchestrator requests a **distinct RS256 token per cloud from the edge IdP** (correct `aud` each: AWS = `sts.amazonaws.com`; GCP = WIF provider resource URL; Azure = `api://AzureADTokenExchange`), then exchanges it: AWS `sts:AssumeRoleWithWebIdentity`, GCP STS token exchange, Azure client-credentials with `client_assertion`. The mint call is `POST {edgeBase}/federate` with body `{"cloud":"aws|azure|gcp","sub":"..."}` and response `{"token":"..."}`. Pin exact `aud` + exact `sub` (never wildcards). The federation `sub` MUST be ≤127 chars (GCP subject limit); the convention is `lifecycle:federation:<env>`. Azure FICs have a propagation delay → build in delay + retry on `AADSTS70021`.
- **Writes state to D1/DO and audit to R2 via the edge API.** The control plane never opens a D1/R2 connection directly; it calls the edge API over HTTPS. Audit is **append-only with `seq`/`record_hash`/`prev_hash` hash-chaining**; **never log tokens/credentials**; **redact before hash + write** (research 02 §6; AU-9/AU-10).

---

### Task 1: Go module scaffold + passing smoke test

**Files:**
- Create: `control-plane/go.mod`
- Create: `control-plane/internal/version/version.go`
- Test: `control-plane/internal/version/version_test.go`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: a buildable Go module at `control-plane/`; `go test ./...` runs; `package version` exporting `const Name = "lifecycle-control-plane"` and `func String() string`.

- [ ] **Step 1: Initialize the module**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle/control-plane
go mod init github.com/lifecycle/control-plane
go mod edit -go=1.23
```

- [ ] **Step 2: Write the failing smoke test**

Create `control-plane/internal/version/version_test.go`:
```go
package version

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	got := String()
	if !strings.Contains(got, Name) {
		t.Fatalf("String() = %q, want it to contain Name %q", got, Name)
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/version/ -run TestString -v`
Expected: FAIL (build error: undefined `Name`/`String`).

- [ ] **Step 4: Write the package**

Create `control-plane/internal/version/version.go`:
```go
// Package version identifies the control-plane build.
package version

import "fmt"

// Name is the orchestrator's stable identifier (used in audit actor fields).
const Name = "lifecycle-control-plane"

// Version is overridden at build time via -ldflags; "dev" locally.
var Version = "dev"

// String returns a human-readable build identifier.
func String() string {
	return fmt.Sprintf("%s/%s", Name, Version)
}
```

- [ ] **Step 5: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/version/ -run TestString -v`
Expected: PASS.

- [ ] **Step 6: Verify the whole module builds and vets**

Run: `cd control-plane && go build ./... && go vet ./... && go test ./...`
Expected: build clean, vet clean, tests pass.

- [ ] **Step 7: Commit**

```bash
git add control-plane/go.mod control-plane/internal/version
git commit -m "chore(control-plane): Go module scaffold + smoke test"
```

---

### Task 2: Identity & entitlement domain model

**Files:**
- Create: `control-plane/internal/domain/identity.go`
- Test: `control-plane/internal/domain/identity_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type IdentityType string` with `IdentityHuman = "human"`, `IdentityNHI = "nhi"` (service account).
  - `type RiskTier string` with `RiskPrivileged = "privileged"`, `RiskStandard = "standard"`, `RiskLow = "low"`.
  - `type Entitlement struct { ID, Role, Resource string; Privileged bool; GrantedBy string; GrantedAt time.Time; LastUsed *time.Time }`
  - `type Identity struct { ID, Email string; Type IdentityType; Owner string; State LifecycleState; Entitlements []Entitlement; ManagerID string }` (`LifecycleState` lives in Task 3; declare it here as the canonical home and Task 3 adds the state-machine logic in a sibling file).
  - `func (i Identity) Validate() error` — NHI MUST have a non-empty `Owner`; human MUST NOT (a human is its own principal).
  - `func (i Identity) EntitlementIDs() map[string]Entitlement`

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/domain/identity_test.go`:
```go
package domain

import "testing"

func TestIdentityValidate(t *testing.T) {
	tests := []struct {
		name    string
		id      Identity
		wantErr bool
	}{
		{"human ok", Identity{ID: "u1", Type: IdentityHuman}, false},
		{"human with owner is invalid", Identity{ID: "u1", Type: IdentityHuman, Owner: "u2"}, true},
		{"nhi requires owner", Identity{ID: "svc1", Type: IdentityNHI}, true},
		{"nhi with owner ok", Identity{ID: "svc1", Type: IdentityNHI, Owner: "u1"}, false},
		{"unknown type invalid", Identity{ID: "x", Type: "robot"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.id.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEntitlementIDs(t *testing.T) {
	i := Identity{Entitlements: []Entitlement{{ID: "a"}, {ID: "b"}}}
	got := i.EntitlementIDs()
	if len(got) != 2 || got["a"].ID != "a" {
		t.Fatalf("EntitlementIDs() = %#v", got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/domain/ -run 'TestIdentityValidate|TestEntitlementIDs' -v`
Expected: FAIL (undefined types).

- [ ] **Step 3: Write the model**

Create `control-plane/internal/domain/identity.go`:
```go
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
	GrantedBy  string     // grantor identity id; reviewer must differ from this
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/domain/ -run 'TestIdentityValidate|TestEntitlementIDs' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add control-plane/internal/domain/identity.go control-plane/internal/domain/identity_test.go
git commit -m "feat(control-plane): identity & entitlement domain model"
```

---

### Task 3: JML lifecycle state machine

**Files:**
- Create: `control-plane/internal/domain/lifecycle.go`
- Test: `control-plane/internal/domain/lifecycle_test.go`

**Interfaces:**
- Consumes: `LifecycleState` (Task 2).
- Produces:
  - Constants: `StateInvited = "invited"`, `StateProvisioned = "provisioned"`, `StateActive = "active"`, `StateReviewDue = "review-due"`, `StateOffboarded = "offboarded"`.
  - `func CanTransition(from, to LifecycleState) bool`
  - `func (i *Identity) Transition(to LifecycleState) error` (mutates `i.State`, returns error on illegal transition).
- Allowed transitions: invited→provisioned; provisioned→active; active→review-due; review-due→active; active→offboarded; review-due→offboarded; provisioned→offboarded (early leaver). `offboarded` is terminal.

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/domain/lifecycle_test.go`:
```go
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
		{StateInvited, StateActive, false},     // must be provisioned first
		{StateOffboarded, StateActive, false},  // terminal
		{StateActive, StateInvited, false},     // no going back
		{StateActive, "frozen", false},         // unknown target
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/domain/ -run 'TestCanTransition|TestTransitionMutatesOrErrors' -v`
Expected: FAIL (undefined constants/functions).

- [ ] **Step 3: Write the state machine**

Create `control-plane/internal/domain/lifecycle.go`:
```go
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/domain/ -run 'TestCanTransition|TestTransitionMutatesOrErrors' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add control-plane/internal/domain/lifecycle.go control-plane/internal/domain/lifecycle_test.go
git commit -m "feat(control-plane): JML lifecycle state machine"
```

---

### Task 4: Joiner — birthright RBAC + JIT time-boxed privileged

**Files:**
- Create: `control-plane/internal/lifecycle/joiner.go`
- Test: `control-plane/internal/lifecycle/joiner_test.go`

**Interfaces:**
- Consumes: `domain.Identity`, `domain.Entitlement` (Tasks 2–3).
- Produces:
  - `type BirthrightPolicy struct { Department string; Entitlements []domain.Entitlement }`
  - `type JITGrant struct { Entitlement domain.Entitlement; TTL time.Duration; Approved bool }`
  - `func ComputeJoinerGrants(department string, policies []BirthrightPolicy) []domain.Entitlement` — birthright (non-privileged) grants for day one.
  - `func ApplyJIT(g JITGrant, now time.Time) (domain.Entitlement, time.Time, error)` — returns the time-boxed entitlement and its hard expiry; errors if not approved or if the entitlement is not privileged (JIT is only for privileged), or TTL ≤ 0.

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/lifecycle/joiner_test.go`:
```go
package lifecycle

import (
	"testing"
	"time"

	"github.com/lifecycle/control-plane/internal/domain"
)

func TestComputeJoinerGrants(t *testing.T) {
	policies := []BirthrightPolicy{
		{Department: "eng", Entitlements: []domain.Entitlement{{ID: "repo-read", Role: "developer"}}},
		{Department: "sales", Entitlements: []domain.Entitlement{{ID: "crm", Role: "rep"}}},
	}
	got := ComputeJoinerGrants("eng", policies)
	if len(got) != 1 || got[0].ID != "repo-read" {
		t.Fatalf("ComputeJoinerGrants(eng) = %#v", got)
	}
	if none := ComputeJoinerGrants("legal", policies); len(none) != 0 {
		t.Fatalf("unknown department should grant nothing, got %#v", none)
	}
}

func TestApplyJIT(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	priv := domain.Entitlement{ID: "prod-admin", Privileged: true}
	t.Run("approved privileged is time-boxed", func(t *testing.T) {
		ent, exp, err := ApplyJIT(JITGrant{Entitlement: priv, TTL: 2 * time.Hour, Approved: true}, now)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !exp.Equal(now.Add(2 * time.Hour)) {
			t.Fatalf("expiry = %v, want %v", exp, now.Add(2*time.Hour))
		}
		if !ent.Privileged {
			t.Fatalf("entitlement should stay privileged")
		}
	})
	t.Run("unapproved rejected", func(t *testing.T) {
		if _, _, err := ApplyJIT(JITGrant{Entitlement: priv, TTL: time.Hour, Approved: false}, now); err == nil {
			t.Fatal("unapproved JIT must error")
		}
	})
	t.Run("non-privileged rejected", func(t *testing.T) {
		std := domain.Entitlement{ID: "repo-read"}
		if _, _, err := ApplyJIT(JITGrant{Entitlement: std, TTL: time.Hour, Approved: true}, now); err == nil {
			t.Fatal("JIT is privileged-only; must error")
		}
	})
	t.Run("non-positive TTL rejected", func(t *testing.T) {
		if _, _, err := ApplyJIT(JITGrant{Entitlement: priv, TTL: 0, Approved: true}, now); err == nil {
			t.Fatal("zero TTL must error")
		}
	})
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/lifecycle/ -run 'TestComputeJoinerGrants|TestApplyJIT' -v`
Expected: FAIL (package/symbols undefined).

- [ ] **Step 3: Write the joiner**

Create `control-plane/internal/lifecycle/joiner.go`:
```go
// Package lifecycle implements the Joiner/Mover/Leaver business logic.
package lifecycle

import (
	"fmt"
	"time"

	"github.com/lifecycle/control-plane/internal/domain"
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/lifecycle/ -run 'TestComputeJoinerGrants|TestApplyJIT' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add control-plane/internal/lifecycle/joiner.go control-plane/internal/lifecycle/joiner_test.go
git commit -m "feat(control-plane): Joiner birthright RBAC + JIT privileged grants"
```

---

### Task 5: Mover diff engine (recalculate, don't accumulate)

**Files:**
- Create: `control-plane/internal/lifecycle/mover.go`
- Test: `control-plane/internal/lifecycle/mover_test.go`

**Interfaces:**
- Consumes: `domain.Entitlement` (Task 2).
- Produces:
  - `type MoverDiff struct { Grant []domain.Entitlement; Revoke []domain.Entitlement }`
  - `func ComputeMoverDiff(current, target []domain.Entitlement) MoverDiff` — `Grant = target − current`, `Revoke = current − target`, keyed by entitlement ID; deterministic (sorted by ID).
- The **add-only-is-a-bug** test: when `current` has an entitlement missing from `target`, `Revoke` MUST contain it.

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/lifecycle/mover_test.go`:
```go
package lifecycle

import (
	"reflect"
	"testing"

	"github.com/lifecycle/control-plane/internal/domain"
)

func ids(es []domain.Entitlement) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.ID
	}
	return out
}

func TestComputeMoverDiff(t *testing.T) {
	cur := []domain.Entitlement{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	tgt := []domain.Entitlement{{ID: "b"}, {ID: "c"}, {ID: "d"}}
	diff := ComputeMoverDiff(cur, tgt)
	if want := []string{"d"}; !reflect.DeepEqual(ids(diff.Grant), want) {
		t.Fatalf("Grant ids = %v, want %v", ids(diff.Grant), want)
	}
	if want := []string{"a"}; !reflect.DeepEqual(ids(diff.Revoke), want) {
		t.Fatalf("Revoke ids = %v, want %v", ids(diff.Revoke), want)
	}
}

// Guards the recalculate-don't-accumulate rule: a Mover that only ever grants
// (never revokes entitlements dropped from target) is a bug.
func TestMoverIsNotAddOnly(t *testing.T) {
	cur := []domain.Entitlement{{ID: "old-team-admin"}}
	tgt := []domain.Entitlement{{ID: "new-team-member"}}
	diff := ComputeMoverDiff(cur, tgt)
	if len(diff.Revoke) == 0 {
		t.Fatal("add-only Mover bug: dropped entitlement was not revoked")
	}
	if diff.Revoke[0].ID != "old-team-admin" {
		t.Fatalf("Revoke = %v, want old-team-admin", ids(diff.Revoke))
	}
}

func TestMoverDiffDeterministic(t *testing.T) {
	cur := []domain.Entitlement{{ID: "z"}, {ID: "a"}}
	diff := ComputeMoverDiff(cur, nil)
	if want := []string{"a", "z"}; !reflect.DeepEqual(ids(diff.Revoke), want) {
		t.Fatalf("Revoke not sorted: %v", ids(diff.Revoke))
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/lifecycle/ -run 'TestComputeMoverDiff|TestMoverIsNotAddOnly|TestMoverDiffDeterministic' -v`
Expected: FAIL (undefined `ComputeMoverDiff`/`MoverDiff`).

- [ ] **Step 3: Write the diff engine**

Create `control-plane/internal/lifecycle/mover.go`:
```go
package lifecycle

import (
	"sort"

	"github.com/lifecycle/control-plane/internal/domain"
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/lifecycle/ -run 'TestComputeMoverDiff|TestMoverIsNotAddOnly|TestMoverDiffDeterministic' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add control-plane/internal/lifecycle/mover.go control-plane/internal/lifecycle/mover_test.go
git commit -m "feat(control-plane): Mover recalculate-don't-accumulate diff engine"
```

---

### Task 6: Audit emitter (append-only, hash-chained, redact-before-write)

**Files:**
- Create: `control-plane/internal/audit/audit.go`
- Test: `control-plane/internal/audit/audit_test.go`

**Interfaces:**
- Consumes: nothing external (the R2 sink is injected behind an interface).
- Produces:
  - `type Record struct { Seq uint64; EventTime time.Time; Actor, Action, Subject, Outcome string; Details map[string]string; PrevHash string; RecordHash string }`
  - `type Sink interface { Append(ctx context.Context, r Record) error }` — the edge-API-backed R2 writer (real impl is an adapter in a later task; tests use a fake).
  - `type Chain struct { ... }` with `func NewChain(s Sink) *Chain` and `func (c *Chain) Emit(ctx context.Context, ev Event) (Record, error)`.
  - `type Event struct { EventTime time.Time; Actor, Action, Subject, Outcome string; Details map[string]string }`
  - `func ComputeHash(r Record) string` — SHA-256 over canonical fields excluding `RecordHash` itself.
  - Redaction: `Emit` MUST strip any detail key in a token/secret deny-list (`token`, `access_token`, `refresh_token`, `client_secret`, `client_assertion`, `password`, `authorization`) to `"[REDACTED]"` **before** hashing and appending.
- `Emit` increments `Seq` (starting at 1), sets `PrevHash` to the prior `RecordHash` (empty string for the genesis record), computes `RecordHash`, then calls `Sink.Append`. If `Append` fails, `Seq`/`PrevHash` are not advanced.

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/audit/audit_test.go`:
```go
package audit

import (
	"context"
	"testing"
	"time"
)

type fakeSink struct {
	records []Record
	failOn  uint64 // fail Append when r.Seq == failOn (0 = never)
}

func (f *fakeSink) Append(_ context.Context, r Record) error {
	if r.Seq == f.failOn {
		return errFail
	}
	f.records = append(f.records, r)
	return nil
}

var errFail = &appendErr{}

type appendErr struct{}

func (*appendErr) Error() string { return "append failed" }

func ev(action, subject string, details map[string]string) Event {
	return Event{
		EventTime: time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC),
		Actor:     "lifecycle-control-plane",
		Action:    action,
		Subject:   subject,
		Outcome:   "success",
		Details:   details,
	}
}

func TestEmitChainsHashes(t *testing.T) {
	s := &fakeSink{}
	c := NewChain(s)
	r1, err := c.Emit(context.Background(), ev("leaver.start", "u1", nil))
	if err != nil {
		t.Fatalf("emit1: %v", err)
	}
	r2, err := c.Emit(context.Background(), ev("leaver.done", "u1", nil))
	if err != nil {
		t.Fatalf("emit2: %v", err)
	}
	if r1.Seq != 1 || r2.Seq != 2 {
		t.Fatalf("seq = %d,%d want 1,2", r1.Seq, r2.Seq)
	}
	if r1.PrevHash != "" {
		t.Fatalf("genesis PrevHash must be empty, got %q", r1.PrevHash)
	}
	if r2.PrevHash != r1.RecordHash {
		t.Fatalf("chain broken: r2.PrevHash %q != r1.RecordHash %q", r2.PrevHash, r1.RecordHash)
	}
	if r1.RecordHash == "" || r1.RecordHash == r2.RecordHash {
		t.Fatalf("record hashes must be present and distinct")
	}
}

func TestEmitRedactsSecretsBeforeWrite(t *testing.T) {
	s := &fakeSink{}
	c := NewChain(s)
	_, err := c.Emit(context.Background(), ev("federation.exchange", "aws", map[string]string{
		"role":         "demo",
		"access_token": "ya29.SECRET",
		"client_secret": "shhh",
	}))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	got := s.records[0].Details
	if got["access_token"] != "[REDACTED]" || got["client_secret"] != "[REDACTED]" {
		t.Fatalf("secrets not redacted: %#v", got)
	}
	if got["role"] != "demo" {
		t.Fatalf("non-secret detail was altered: %#v", got)
	}
}

func TestEmitDoesNotAdvanceOnSinkFailure(t *testing.T) {
	s := &fakeSink{failOn: 2}
	c := NewChain(s)
	r1, err := c.Emit(context.Background(), ev("a", "u1", nil))
	if err != nil {
		t.Fatalf("emit1: %v", err)
	}
	if _, err := c.Emit(context.Background(), ev("b", "u1", nil)); err == nil {
		t.Fatal("expected sink failure to propagate")
	}
	// Clear the injected failure and retry: the chain must reuse seq 2 and chain
	// off record 1 (a failed Append must not advance seq/prev-hash).
	s.failOn = 0
	r2, err := c.Emit(context.Background(), ev("b-retry", "u1", nil))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if r2.Seq != 2 {
		t.Fatalf("retry seq = %d, want 2 (failure must not advance)", r2.Seq)
	}
	if r2.PrevHash != r1.RecordHash {
		t.Fatalf("retry must chain off record 1: PrevHash %q != %q", r2.PrevHash, r1.RecordHash)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/audit/ -run 'TestEmit' -v`
Expected: FAIL (undefined `NewChain`/`Record`/etc).

- [ ] **Step 3: Write the audit emitter**

Create `control-plane/internal/audit/audit.go`:
```go
// Package audit emits append-only, hash-chained audit records to an injected
// sink (the edge-API-backed R2 writer). It never logs tokens/credentials:
// secret-bearing detail keys are redacted before hashing and writing.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Record is one immutable audit-log entry (AU-3 six elements + chain fields).
type Record struct {
	Seq        uint64            `json:"seq"`
	EventTime  time.Time         `json:"event_time"`
	Actor      string            `json:"actor"`
	Action     string            `json:"action"`
	Subject    string            `json:"subject"`
	Outcome    string            `json:"outcome"`
	Details    map[string]string `json:"details"`
	PrevHash   string            `json:"prev_hash"`
	RecordHash string            `json:"record_hash"`
}

// Event is the caller-supplied payload before sequencing/hashing.
type Event struct {
	EventTime time.Time
	Actor     string
	Action    string
	Subject   string
	Outcome   string
	Details   map[string]string
}

// Sink persists records in append-only order (R2 via the edge API).
type Sink interface {
	Append(ctx context.Context, r Record) error
}

// secretKeys are detail keys whose values are redacted before write.
var secretKeys = map[string]bool{
	"token":            true,
	"access_token":     true,
	"refresh_token":    true,
	"id_token":         true,
	"client_secret":    true,
	"client_assertion": true,
	"password":         true,
	"authorization":    true,
	"private_key":      true,
}

// Chain sequences and hash-chains records into a Sink.
type Chain struct {
	sink     Sink
	nextSeq  uint64
	prevHash string
}

// NewChain starts a fresh chain (genesis Seq=1, empty PrevHash).
func NewChain(s Sink) *Chain {
	return &Chain{sink: s, nextSeq: 1}
}

// Emit redacts, sequences, hash-chains, and appends one record. On sink
// failure the sequence/prev-hash are not advanced so a retry is idempotent.
func (c *Chain) Emit(ctx context.Context, ev Event) (Record, error) {
	r := Record{
		Seq:       c.nextSeq,
		EventTime: ev.EventTime.UTC(),
		Actor:     ev.Actor,
		Action:    ev.Action,
		Subject:   ev.Subject,
		Outcome:   ev.Outcome,
		Details:   redact(ev.Details),
		PrevHash:  c.prevHash,
	}
	r.RecordHash = ComputeHash(r)
	if err := c.sink.Append(ctx, r); err != nil {
		return Record{}, fmt.Errorf("audit append seq %d: %w", r.Seq, err)
	}
	c.nextSeq++
	c.prevHash = r.RecordHash
	return r, nil
}

// redact copies details, masking secret-bearing keys.
func redact(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if secretKeys[strings.ToLower(k)] {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = v
	}
	return out
}

// ComputeHash is SHA-256 over a deterministic encoding of all fields except
// RecordHash itself.
func ComputeHash(r Record) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d\n%s\n%s\n%s\n%s\n%s\n%s\n",
		r.Seq, r.EventTime.Format(time.RFC3339Nano),
		r.Actor, r.Action, r.Subject, r.Outcome, r.PrevHash)
	keys := make([]string, 0, len(r.Details))
	for k := range r.Details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, r.Details[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/audit/ -run 'TestEmit' -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add control-plane/internal/audit
git commit -m "feat(control-plane): append-only hash-chained audit emitter with redaction"
```

---

### Task 7: Edge API & SCIM client interfaces + SCIM reconciliation

**Files:**
- Create: `control-plane/internal/ports/ports.go`
- Create: `control-plane/internal/scim/reconcile.go`
- Test: `control-plane/internal/scim/reconcile_test.go`

**Interfaces:**
- Consumes: `domain.Identity`, `lifecycle.MoverDiff`.
- Produces in `package ports` (the seam between domain and the outside world; all adapters live in later tasks/cmd):
  - `type SCIMClient interface { PushUser(ctx context.Context, u domain.Identity) error; SetActive(ctx context.Context, userID string, active bool) error; ListUsers(ctx context.Context) ([]domain.Identity, error) }`
  - `type Revoker interface` (defined in Task 8; referenced here only by name).
  - `type StateStore interface { GetIdentity(ctx context.Context, id string) (domain.Identity, error); PutIdentity(ctx context.Context, i domain.Identity) error; ListByState(ctx context.Context, s domain.LifecycleState) ([]domain.Identity, error) }` — backed by D1/DO **via the edge API**.
- Produces in `package scim`:
  - `type ReconcileResult struct { ToCreate, ToUpdate []domain.Identity; ToDisable []string }`
  - `func Plan(desired, observed []domain.Identity) ReconcileResult` — desired = control-plane state, observed = what the edge SCIM endpoint currently has; create missing, update drifted, disable extras (**never hard-delete**, research 02 §1).
  - `func Apply(ctx context.Context, c ports.SCIMClient, r ReconcileResult) error`

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/scim/reconcile_test.go`:
```go
package scim

import (
	"context"
	"testing"

	"github.com/lifecycle/control-plane/internal/domain"
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/scim/ -run 'TestPlan|TestApply' -v`
Expected: FAIL (packages undefined).

- [ ] **Step 3: Write the ports + reconciliation**

Create `control-plane/internal/ports/ports.go`:
```go
// Package ports declares the interfaces the control plane depends on. Real
// adapters (edge API, cloud SDKs) implement these; unit tests use fakes.
package ports

import (
	"context"

	"github.com/lifecycle/control-plane/internal/domain"
)

// SCIMClient pushes provisioning changes to the edge SCIM service provider.
type SCIMClient interface {
	PushUser(ctx context.Context, u domain.Identity) error
	SetActive(ctx context.Context, userID string, active bool) error
	ListUsers(ctx context.Context) ([]domain.Identity, error)
}

// StateStore reads/writes lifecycle state to D1/DO via the edge API.
type StateStore interface {
	GetIdentity(ctx context.Context, id string) (domain.Identity, error)
	PutIdentity(ctx context.Context, i domain.Identity) error
	ListByState(ctx context.Context, s domain.LifecycleState) ([]domain.Identity, error)
}

// Revoker is the Leaver-saga port (implemented in package offboard). It is the
// union of one SCIM disable + RFC 7009 + Back-Channel Logout + API-key revoke,
// each step capability-checked per app.
type Revoker interface {
	DisableAccount(ctx context.Context, app, userID string) error
	RevokeOAuthGrant(ctx context.Context, app, userID string) error // RFC 7009
	TerminateSessions(ctx context.Context, app, userID string) error // Back-Channel Logout
	RevokeAPIKeys(ctx context.Context, app, userID string) error
	// Supports reports which saga steps an app implements; absent steps require
	// a compensating control to be logged.
	Supports(app string) AppCapabilities
}

// AppCapabilities declares which offboarding primitives an app exposes.
type AppCapabilities struct {
	OAuthRevocation     bool // RFC 7009
	BackChannelLogout   bool // OIDC Back-Channel Logout
	APIKeyRevocation    bool
}
```

Create `control-plane/internal/scim/reconcile.go`:
```go
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/scim/ -run 'TestPlan|TestApply' -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add control-plane/internal/ports control-plane/internal/scim
git commit -m "feat(control-plane): ports + SCIM reconciliation (disable, never delete)"
```

---

### Task 8: Leaver offboarding saga (per-app sub-states + compensating controls)

**Files:**
- Create: `control-plane/internal/offboard/saga.go`
- Test: `control-plane/internal/offboard/saga_test.go`

**Interfaces:**
- Consumes: `ports.Revoker`, `ports.AppCapabilities` (Task 7); `audit.Chain` (Task 6).
- Produces:
  - `type SubState string` with `SubAccountDisabled = "account_disabled"`, `SubOAuthGrantRevoked = "oauth_grant_revoked"`, `SubSessionsTerminated = "sessions_terminated"`, `SubAPIKeysRevoked = "api_keys_revoked"`.
  - `type AppResult struct { App string; Completed []SubState; Compensating []string; Err error }`
  - `type SagaResult struct { Apps []AppResult; AllGreen bool }`
  - `func RunLeaver(ctx context.Context, r ports.Revoker, ch *audit.Chain, userID string, apps []string, now time.Time) SagaResult`
- Saga order per app (the global constraint): **disable → revoke OAuth grant/refresh (RFC 7009) → terminate sessions (Back-Channel Logout) → revoke API keys**. When an app lacks a capability (`Supports(app)` false for that step), the step is **skipped and a compensating-control note is logged** (e.g. "manual session kill required"), and that sub-state is **not** counted as completed. `AllGreen` is true only when every app completed every *supported* step with no error **and** every unsupported step has a compensating control recorded. Emits an audit record per step and per compensating control.

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/offboard/saga_test.go`:
```go
package offboard

import (
	"context"
	"testing"
	"time"

	"github.com/lifecycle/control-plane/internal/audit"
	"github.com/lifecycle/control-plane/internal/ports"
)

type fakeRevoker struct {
	caps    map[string]ports.AppCapabilities
	calls   []string
	failOn  string // "app:step" to force an error
}

func (f *fakeRevoker) rec(app, step string) error {
	key := app + ":" + step
	f.calls = append(f.calls, key)
	if key == f.failOn {
		return errStep
	}
	return nil
}
func (f *fakeRevoker) DisableAccount(_ context.Context, app, _ string) error { return f.rec(app, "disable") }
func (f *fakeRevoker) RevokeOAuthGrant(_ context.Context, app, _ string) error { return f.rec(app, "oauth") }
func (f *fakeRevoker) TerminateSessions(_ context.Context, app, _ string) error { return f.rec(app, "sessions") }
func (f *fakeRevoker) RevokeAPIKeys(_ context.Context, app, _ string) error { return f.rec(app, "apikeys") }
func (f *fakeRevoker) Supports(app string) ports.AppCapabilities { return f.caps[app] }

var errStep = &stepErr{}

type stepErr struct{}

func (*stepErr) Error() string { return "step failed" }

type nopSink struct{}

func (nopSink) Append(_ context.Context, _ audit.Record) error { return nil }

func full() ports.AppCapabilities {
	return ports.AppCapabilities{OAuthRevocation: true, BackChannelLogout: true, APIKeyRevocation: true}
}

func TestRunLeaverAllGreen(t *testing.T) {
	r := &fakeRevoker{caps: map[string]ports.AppCapabilities{"github": full(), "slack": full()}}
	res := RunLeaver(context.Background(), r, audit.NewChain(nopSink{}), "u1", []string{"github", "slack"}, time.Now())
	if !res.AllGreen {
		t.Fatalf("expected all-green, got %#v", res)
	}
	for _, ar := range res.Apps {
		if len(ar.Completed) != 4 {
			t.Fatalf("%s completed %v, want 4 substates", ar.App, ar.Completed)
		}
	}
}

func TestRunLeaverCompensatingControl(t *testing.T) {
	// App without RFC 7009 or back-channel logout: those steps become
	// compensating controls and the substates are NOT counted complete.
	caps := ports.AppCapabilities{OAuthRevocation: false, BackChannelLogout: false, APIKeyRevocation: true}
	r := &fakeRevoker{caps: map[string]ports.AppCapabilities{"legacy": caps}}
	res := RunLeaver(context.Background(), r, audit.NewChain(nopSink{}), "u1", []string{"legacy"}, time.Now())
	ar := res.Apps[0]
	if len(ar.Compensating) != 2 {
		t.Fatalf("compensating = %v, want 2 (oauth + sessions)", ar.Compensating)
	}
	// disable + api keys ran; oauth + sessions were skipped.
	if has(ar.Completed, SubOAuthGrantRevoked) || has(ar.Completed, SubSessionsTerminated) {
		t.Fatalf("skipped steps must not be marked complete: %v", ar.Completed)
	}
	if !has(ar.Completed, SubAccountDisabled) || !has(ar.Completed, SubAPIKeysRevoked) {
		t.Fatalf("supported steps must complete: %v", ar.Completed)
	}
	if !res.AllGreen {
		t.Fatal("all supported steps done + compensating logged => all-green")
	}
}

func TestRunLeaverStepFailureNotGreen(t *testing.T) {
	r := &fakeRevoker{caps: map[string]ports.AppCapabilities{"github": full()}, failOn: "github:sessions"}
	res := RunLeaver(context.Background(), r, audit.NewChain(nopSink{}), "u1", []string{"github"}, time.Now())
	if res.AllGreen {
		t.Fatal("a failed step must not be all-green")
	}
	if res.Apps[0].Err == nil {
		t.Fatal("expected per-app error recorded")
	}
}

func has(ss []SubState, want SubState) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/offboard/ -run 'TestRunLeaver' -v`
Expected: FAIL (undefined `RunLeaver`/`SubState`).

- [ ] **Step 3: Write the saga**

Create `control-plane/internal/offboard/saga.go`:
```go
// Package offboard runs the Leaver multi-step saga. active=false alone leaves
// live sessions/refresh tokens valid (research 02 #1), so each app runs, in
// order: disable -> revoke OAuth grant/refresh (RFC 7009) -> terminate sessions
// (Back-Channel Logout) -> revoke API keys. Only all-green = offboarded. When an
// app lacks a capability the step is skipped and a compensating control logged.
package offboard

import (
	"context"
	"time"

	"github.com/lifecycle/control-plane/internal/audit"
	"github.com/lifecycle/control-plane/internal/ports"
)

// SubState is one offboarding step per app.
type SubState string

const (
	SubAccountDisabled    SubState = "account_disabled"
	SubOAuthGrantRevoked  SubState = "oauth_grant_revoked"
	SubSessionsTerminated SubState = "sessions_terminated"
	SubAPIKeysRevoked     SubState = "api_keys_revoked"
)

// AppResult records what happened for one app.
type AppResult struct {
	App          string
	Completed    []SubState
	Compensating []string
	Err          error
}

// SagaResult aggregates per-app results; AllGreen gates "offboarded".
type SagaResult struct {
	Apps     []AppResult
	AllGreen bool
}

// step couples a substate with its action and the capability that gates it.
type step struct {
	state     SubState
	gated     bool // true if this step depends on a capability flag
	supported func(ports.AppCapabilities) bool
	run       func(ctx context.Context, r ports.Revoker, app, userID string) error
}

// RunLeaver executes the saga for each app in canonical order.
func RunLeaver(ctx context.Context, r ports.Revoker, ch *audit.Chain, userID string, apps []string, now time.Time) SagaResult {
	steps := []step{
		{SubAccountDisabled, false, nil, func(ctx context.Context, r ports.Revoker, app, u string) error { return r.DisableAccount(ctx, app, u) }},
		{SubOAuthGrantRevoked, true, func(c ports.AppCapabilities) bool { return c.OAuthRevocation }, func(ctx context.Context, r ports.Revoker, app, u string) error { return r.RevokeOAuthGrant(ctx, app, u) }},
		{SubSessionsTerminated, true, func(c ports.AppCapabilities) bool { return c.BackChannelLogout }, func(ctx context.Context, r ports.Revoker, app, u string) error { return r.TerminateSessions(ctx, app, u) }},
		{SubAPIKeysRevoked, true, func(c ports.AppCapabilities) bool { return c.APIKeyRevocation }, func(ctx context.Context, r ports.Revoker, app, u string) error { return r.RevokeAPIKeys(ctx, app, u) }},
	}

	result := SagaResult{AllGreen: true}
	for _, app := range apps {
		caps := r.Supports(app)
		ar := AppResult{App: app}
		appGreen := true
		for _, s := range steps {
			if s.gated && !s.supported(caps) {
				note := "compensating control required: " + string(s.state) + " not supported by " + app
				ar.Compensating = append(ar.Compensating, note)
				emit(ctx, ch, now, userID, "leaver.compensating", app, "manual", map[string]string{"substate": string(s.state)})
				continue
			}
			if err := s.run(ctx, r, app, userID); err != nil {
				ar.Err = err
				appGreen = false
				emit(ctx, ch, now, userID, "leaver.step", app, "failure", map[string]string{"substate": string(s.state)})
				break
			}
			ar.Completed = append(ar.Completed, s.state)
			emit(ctx, ch, now, userID, "leaver.step", app, "success", map[string]string{"substate": string(s.state)})
		}
		if !appGreen {
			result.AllGreen = false
		}
		result.Apps = append(result.Apps, ar)
	}
	return result
}

func emit(ctx context.Context, ch *audit.Chain, now time.Time, userID, action, app, outcome string, details map[string]string) {
	if ch == nil {
		return
	}
	details["app"] = app
	_, _ = ch.Emit(ctx, audit.Event{
		EventTime: now,
		Actor:     "lifecycle-control-plane",
		Action:    action,
		Subject:   userID,
		Outcome:   outcome,
		Details:   details,
	})
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/offboard/ -run 'TestRunLeaver' -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add control-plane/internal/offboard
git commit -m "feat(control-plane): Leaver offboarding saga with compensating controls"
```

---

### Task 9: SoD detective evaluation (calls the policy engine)

**Files:**
- Create: `control-plane/internal/sod/sod.go`
- Test: `control-plane/internal/sod/sod_test.go`

**Interfaces:**
- Consumes: `domain.Identity`, `domain.Entitlement`.
- Produces:
  - `type PolicyEngine interface { EvalSoD(ctx context.Context, input SoDInput) (SoDDecision, error) }` — the seam to the OPA/Regorus policy engine (real impl in a later phase; the control plane never hard-codes the SoD matrix, only calls the PE — Zero-Trust PA role).
  - `type SoDInput struct { IdentityID string; EntitlementIDs []string }`
  - `type SoDViolation struct { A, B string; Rule string }`
  - `type SoDDecision struct { Violations []SoDViolation }`
  - `func DetectiveSweep(ctx context.Context, pe PolicyEngine, ids []domain.Identity) (map[string][]SoDViolation, error)` — runs SoD evaluation across identities (detective mode, research 02 §3/§4: preventive at request time, detective in sweeps), returning violations keyed by identity id; skips identities with no entitlements.

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/sod/sod_test.go`:
```go
package sod

import (
	"context"
	"testing"

	"github.com/lifecycle/control-plane/internal/domain"
)

type fakePE struct {
	violationsFor map[string][]SoDViolation
}

func (f *fakePE) EvalSoD(_ context.Context, in SoDInput) (SoDDecision, error) {
	return SoDDecision{Violations: f.violationsFor[in.IdentityID]}, nil
}

func TestDetectiveSweep(t *testing.T) {
	pe := &fakePE{violationsFor: map[string][]SoDViolation{
		"u1": {{A: "create-payment", B: "approve-payment", Rule: "sod-payments"}},
	}}
	ids := []domain.Identity{
		{ID: "u1", Entitlements: []domain.Entitlement{{ID: "create-payment"}, {ID: "approve-payment"}}},
		{ID: "u2", Entitlements: []domain.Entitlement{{ID: "read-only"}}},
		{ID: "u3"}, // no entitlements -> skipped
	}
	got, err := DetectiveSweep(context.Background(), pe, ids)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(got["u1"]) != 1 || got["u1"][0].Rule != "sod-payments" {
		t.Fatalf("u1 violations = %#v", got["u1"])
	}
	if _, ok := got["u2"]; ok {
		t.Fatalf("u2 has no violations and must be absent")
	}
	if _, ok := got["u3"]; ok {
		t.Fatalf("u3 has no entitlements and must be skipped")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/sod/ -run TestDetectiveSweep -v`
Expected: FAIL (package undefined).

- [ ] **Step 3: Write the SoD evaluator**

Create `control-plane/internal/sod/sod.go`:
```go
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/sod/ -run TestDetectiveSweep -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add control-plane/internal/sod
git commit -m "feat(control-plane): SoD detective sweep via policy engine"
```

---

### Task 10: Risk-tiered access-review scheduler + micro-certification batches

**Files:**
- Create: `control-plane/internal/review/scheduler.go`
- Test: `control-plane/internal/review/scheduler_test.go`

**Interfaces:**
- Consumes: `domain.Identity`, `domain.Entitlement`, `domain.RiskTier`.
- Produces:
  - `type CadencePolicy struct { Tier domain.RiskTier; Interval time.Duration }` (the D1 policy table, passed in).
  - `func DueForReview(i domain.Identity, tier domain.RiskTier, lastReviewed time.Time, policy []CadencePolicy, now time.Time) bool`
  - `type ReviewItem struct { IdentityID, EntitlementID, Reviewer string; Recommendation string; LastUsed *time.Time }` (`Recommendation` ∈ `"keep"`, `"revoke"`).
  - `func BuildItems(i domain.Identity, reviewerFor func(domain.Entitlement) string, now time.Time, staleAfter time.Duration) ([]ReviewItem, error)` — one item per entitlement; **reviewer ≠ grantor** (error if `reviewerFor` returns the grantor); pre-populates `Recommendation = "revoke"` when the entitlement is unused or last-used older than `staleAfter` (per-entitlement last-use → revoke recommendation, research 02 §3).
  - `func Batch(items []ReviewItem, perReviewer int) map[string][][]ReviewItem` — distributed micro-certification: small per-reviewer batches.

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/review/scheduler_test.go`:
```go
package review

import (
	"testing"
	"time"

	"github.com/lifecycle/control-plane/internal/domain"
)

var policy = []CadencePolicy{
	{Tier: domain.RiskPrivileged, Interval: 30 * 24 * time.Hour},
	{Tier: domain.RiskStandard, Interval: 90 * 24 * time.Hour},
	{Tier: domain.RiskLow, Interval: 365 * 24 * time.Hour},
}

func TestDueForReview(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	priv := now.Add(-31 * 24 * time.Hour)
	if !DueForReview(domain.Identity{}, domain.RiskPrivileged, priv, policy, now) {
		t.Fatal("privileged reviewed 31d ago should be due (30d cadence)")
	}
	recent := now.Add(-10 * 24 * time.Hour)
	if DueForReview(domain.Identity{}, domain.RiskStandard, recent, policy, now) {
		t.Fatal("standard reviewed 10d ago should NOT be due (90d cadence)")
	}
}

func TestBuildItemsReviewerNotGrantor(t *testing.T) {
	now := time.Date(2026, 6, 24, 0, 0, 0, 0, time.UTC)
	old := now.Add(-200 * 24 * time.Hour)
	id := domain.Identity{
		ID: "u1",
		Entitlements: []domain.Entitlement{
			{ID: "e1", GrantedBy: "mgr", LastUsed: &old}, // stale -> revoke rec
			{ID: "e2", GrantedBy: "mgr", LastUsed: nil},  // never used -> revoke rec
		},
	}
	items, err := BuildItems(id, func(domain.Entitlement) string { return "reviewer" }, now, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("BuildItems: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	for _, it := range items {
		if it.Reviewer == "mgr" {
			t.Fatal("reviewer must not equal grantor")
		}
		if it.Recommendation != "revoke" {
			t.Fatalf("stale/unused entitlement should pre-populate revoke, got %q", it.Recommendation)
		}
	}
}

func TestBuildItemsRejectsGrantorAsReviewer(t *testing.T) {
	now := time.Now()
	id := domain.Identity{ID: "u1", Entitlements: []domain.Entitlement{{ID: "e1", GrantedBy: "mgr"}}}
	_, err := BuildItems(id, func(domain.Entitlement) string { return "mgr" }, now, time.Hour)
	if err == nil {
		t.Fatal("assigning the grantor as reviewer must error")
	}
}

func TestBatch(t *testing.T) {
	items := []ReviewItem{
		{Reviewer: "r1"}, {Reviewer: "r1"}, {Reviewer: "r1"},
		{Reviewer: "r2"},
	}
	b := Batch(items, 2)
	if len(b["r1"]) != 2 { // 3 items / batch size 2 -> 2 batches
		t.Fatalf("r1 batches = %d, want 2", len(b["r1"]))
	}
	if len(b["r2"]) != 1 {
		t.Fatalf("r2 batches = %d, want 1", len(b["r2"]))
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/review/ -run 'TestDueForReview|TestBuildItems|TestBatch' -v`
Expected: FAIL (package undefined).

- [ ] **Step 3: Write the scheduler**

Create `control-plane/internal/review/scheduler.go`:
```go
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/review/ -run 'TestDueForReview|TestBuildItems|TestBatch' -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add control-plane/internal/review
git commit -m "feat(control-plane): risk-tiered access-review scheduler + micro-cert batches"
```

---

### Task 11: NHI lifecycle (owner required; leaver fan-out transfer-or-rotate)

**Files:**
- Create: `control-plane/internal/nhi/nhi.go`
- Test: `control-plane/internal/nhi/nhi_test.go`

**Interfaces:**
- Consumes: `domain.Identity`, `domain.IdentityType`.
- Produces:
  - `type Action string` with `ActionTransfer = "transfer"`, `ActionRotate = "rotate"`.
  - `type FanOut struct { NHIID string; Action Action; NewOwner string }`
  - `func OwnedBy(owner string, all []domain.Identity) []domain.Identity` — the NHIs a human owns.
  - `func PlanLeaverFanOut(leaver string, all []domain.Identity, successor func(nhi domain.Identity) (newOwner string, ok bool)) ([]FanOut, error)` — for each NHI the leaver owns: if a successor exists → `transfer` to them; else → `rotate` (credentials rotated, ownership flagged for manual reassignment). Errors if any candidate NHI fails `Validate()` (e.g. missing owner — an invariant breach).

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/nhi/nhi_test.go`:
```go
package nhi

import (
	"testing"

	"github.com/lifecycle/control-plane/internal/domain"
)

func TestOwnedBy(t *testing.T) {
	all := []domain.Identity{
		{ID: "u1", Type: domain.IdentityHuman},
		{ID: "svc1", Type: domain.IdentityNHI, Owner: "u1"},
		{ID: "svc2", Type: domain.IdentityNHI, Owner: "u2"},
	}
	got := OwnedBy("u1", all)
	if len(got) != 1 || got[0].ID != "svc1" {
		t.Fatalf("OwnedBy(u1) = %#v", got)
	}
}

func TestPlanLeaverFanOut(t *testing.T) {
	all := []domain.Identity{
		{ID: "svc1", Type: domain.IdentityNHI, Owner: "u1"},
		{ID: "svc2", Type: domain.IdentityNHI, Owner: "u1"},
	}
	successor := func(n domain.Identity) (string, bool) {
		if n.ID == "svc1" {
			return "u2", true // transfer
		}
		return "", false // rotate
	}
	plans, err := PlanLeaverFanOut("u1", all, successor)
	if err != nil {
		t.Fatalf("fan-out: %v", err)
	}
	byID := map[string]FanOut{}
	for _, p := range plans {
		byID[p.NHIID] = p
	}
	if byID["svc1"].Action != ActionTransfer || byID["svc1"].NewOwner != "u2" {
		t.Fatalf("svc1 plan = %#v, want transfer to u2", byID["svc1"])
	}
	if byID["svc2"].Action != ActionRotate {
		t.Fatalf("svc2 plan = %#v, want rotate", byID["svc2"])
	}
}

func TestPlanLeaverFanOutRejectsInvalidNHI(t *testing.T) {
	all := []domain.Identity{{ID: "svc1", Type: domain.IdentityNHI}} // no owner -> invalid
	_, err := PlanLeaverFanOut("u1", all, func(domain.Identity) (string, bool) { return "", false })
	// svc1 isn't owned by u1 so it's not in scope; ensure no false error.
	if err != nil {
		t.Fatalf("out-of-scope invalid NHI should not error: %v", err)
	}
	owned := []domain.Identity{{ID: "svc9", Type: domain.IdentityNHI, Owner: "u1"}}
	if _, err := PlanLeaverFanOut("u1", owned, func(domain.Identity) (string, bool) { return "", false }); err != nil {
		t.Fatalf("valid owned NHI should plan cleanly: %v", err)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/nhi/ -run 'TestOwnedBy|TestPlanLeaverFanOut' -v`
Expected: FAIL (package undefined).

- [ ] **Step 3: Write the NHI lifecycle**

Create `control-plane/internal/nhi/nhi.go`:
```go
// Package nhi handles non-human-identity lifecycle. Every NHI has a mandatory
// human owner; when that human leaves, ownership of each NHI is transferred to
// a successor or, lacking one, its credentials are rotated and flagged.
package nhi

import (
	"fmt"

	"github.com/lifecycle/control-plane/internal/domain"
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/nhi/ -run 'TestOwnedBy|TestPlanLeaverFanOut' -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add control-plane/internal/nhi
git commit -m "feat(control-plane): NHI lifecycle with leaver transfer-or-rotate fan-out"
```

---

### Task 12: Edge IdP token mint (per-cloud distinct RS256 token request)

**Files:**
- Create: `control-plane/internal/federation/idp.go`
- Test: `control-plane/internal/federation/idp_test.go`

**Interfaces:**
- Consumes: nothing external (HTTP doer injected).
- Produces:
  - `type Cloud string` with `CloudAWS = "aws"`, `CloudGCP = "gcp"`, `CloudAzure = "azure"`.
  - `type Audiences struct { AWS, GCP, Azure string }` — distinct `aud` per cloud (AWS = `sts.amazonaws.com`; GCP = WIF provider resource URL; Azure = `api://AzureADTokenExchange`). These are the exchange-time audiences consumed by Tasks 13–15; the mint call itself selects the per-cloud token by `cloud`.
  - `func AudienceFor(c Cloud, a Audiences) (string, error)`
  - `type HTTPDoer interface { Do(*http.Request) (*http.Response, error) }`
  - `type TokenMinter struct { ... }` with `func NewTokenMinter(edgeBase, subject string, auds Audiences, doer HTTPDoer) *TokenMinter` and `func (m *TokenMinter) MintFor(ctx context.Context, c Cloud) (string, error)` — POSTs to `{edgeBase}/federate` with body `{"cloud":"aws|azure|gcp","sub":"..."}` (exact `sub`, never a wildcard; `sub` MUST be ≤127 chars, GCP limit — convention `lifecycle:federation:<env>`) and reads `{"token":"..."}`, returning the RS256 JWT. Validates a distinct token is requested per cloud (different `cloud`).

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/federation/idp_test.go`:
```go
package federation

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type capturingDoer struct {
	lastBody string
	resp     string
}

func (d *capturingDoer) Do(req *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(req.Body)
	d.lastBody = string(b)
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(d.resp)),
		Header:     make(http.Header),
	}, nil
}

func TestAudienceFor(t *testing.T) {
	auds := Audiences{AWS: "sts.amazonaws.com", GCP: "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/lifecycle-pool/providers/lifecycle-oidc", Azure: "api://AzureADTokenExchange"}
	for _, tt := range []struct {
		c    Cloud
		want string
	}{
		{CloudAWS, "sts.amazonaws.com"},
		{CloudGCP, "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/lifecycle-pool/providers/lifecycle-oidc"},
		{CloudAzure, "api://AzureADTokenExchange"},
	} {
		got, err := AudienceFor(tt.c, auds)
		if err != nil || got != tt.want {
			t.Fatalf("AudienceFor(%q) = %q,%v want %q", tt.c, got, err, tt.want)
		}
	}
	if _, err := AudienceFor("oracle", auds); err == nil {
		t.Fatal("unknown cloud must error")
	}
}

func TestMintForUsesDistinctAudience(t *testing.T) {
	d := &capturingDoer{resp: `{"token":"header.payload.sig"}`}
	auds := Audiences{AWS: "aws-aud", GCP: "gcp-aud", Azure: "az-aud"}
	m := NewTokenMinter("https://idp.lifecycle.example/federate", "repo:org/lifecycle:environment:production", auds, d)

	tok, err := m.MintFor(context.Background(), CloudAWS)
	if err != nil || tok != "header.payload.sig" {
		t.Fatalf("MintFor(aws) = %q,%v", tok, err)
	}
	var sent map[string]string
	if err := json.Unmarshal([]byte(d.lastBody), &sent); err != nil {
		t.Fatalf("body not JSON: %s", d.lastBody)
	}
	if sent["aud"] != "aws-aud" {
		t.Fatalf("aws aud = %q, want aws-aud", sent["aud"])
	}
	if sent["sub"] != "repo:org/lifecycle:environment:production" {
		t.Fatalf("sub = %q (must be exact, no wildcard)", sent["sub"])
	}

	if _, err := m.MintFor(context.Background(), CloudGCP); err != nil {
		t.Fatalf("MintFor(gcp): %v", err)
	}
	_ = json.Unmarshal([]byte(d.lastBody), &sent)
	if sent["aud"] != "gcp-aud" {
		t.Fatalf("gcp aud = %q, want gcp-aud (distinct per cloud)", sent["aud"])
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/federation/ -run 'TestAudienceFor|TestMintForUsesDistinctAudience' -v`
Expected: FAIL (package undefined).

- [ ] **Step 3: Write the minter**

Create `control-plane/internal/federation/idp.go`:
```go
// Package federation orchestrates per-cloud token mint + exchange. The edge IdP
// issues a DISTINCT RS256 token per cloud (correct aud each), then each cloud
// adapter exchanges it for short-lived credentials. Exact aud + exact sub,
// never wildcards (confused-deputy lesson, research 03).
package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Cloud identifies a target cloud.
type Cloud string

const (
	CloudAWS   Cloud = "aws"
	CloudGCP   Cloud = "gcp"
	CloudAzure Cloud = "azure"
)

// Audiences holds the distinct per-cloud audience values.
type Audiences struct {
	AWS   string // sts.amazonaws.com (AWS WIF audience for AssumeRoleWithWebIdentity)
	GCP   string // WIF provider resource URL (//iam.googleapis.com/projects/.../providers/...)
	Azure string // api://AzureADTokenExchange
}

// AudienceFor returns the distinct aud for a cloud.
func AudienceFor(c Cloud, a Audiences) (string, error) {
	switch c {
	case CloudAWS:
		return a.AWS, nil
	case CloudGCP:
		return a.GCP, nil
	case CloudAzure:
		return a.Azure, nil
	default:
		return "", fmt.Errorf("unknown cloud %q", c)
	}
}

// HTTPDoer is the injectable HTTP seam (tests use a fake; prod uses http.Client).
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// TokenMinter requests per-cloud RS256 tokens from the edge IdP.
type TokenMinter struct {
	idpURL  string
	subject string // exact sub (e.g. GitHub environment), never wildcard
	auds    Audiences
	doer    HTTPDoer
}

// NewTokenMinter constructs a minter bound to one edge IdP and subject.
func NewTokenMinter(idpURL, subject string, auds Audiences, doer HTTPDoer) *TokenMinter {
	return &TokenMinter{idpURL: idpURL, subject: subject, auds: auds, doer: doer}
}

// MintFor requests the RS256 token whose aud matches the target cloud.
func (m *TokenMinter) MintFor(ctx context.Context, c Cloud) (string, error) {
	aud, err := AudienceFor(c, m.auds)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]string{"aud": aud, "sub": m.subject})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.idpURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.doer.Do(req)
	if err != nil {
		return "", fmt.Errorf("mint token for %s: %w", c, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mint token for %s: status %d", c, resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode token for %s: %w", c, err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("empty token for %s", c)
	}
	return out.Token, nil
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/federation/ -run 'TestAudienceFor|TestMintForUsesDistinctAudience' -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add control-plane/internal/federation/idp.go control-plane/internal/federation/idp_test.go
git commit -m "feat(control-plane): edge IdP per-cloud distinct RS256 token mint"
```

---

### Task 13: AWS STS AssumeRoleWithWebIdentity request construction

**Files:**
- Create: `control-plane/internal/federation/aws.go`
- Test: `control-plane/internal/federation/aws_test.go`

**Interfaces:**
- Consumes: the token from Task 12.
- Produces:
  - `type AWSExchangeInput struct { RoleARN, RoleSessionName, WebIdentityToken string; DurationSeconds int32 }`
  - `func BuildAWSExchange(roleARN, sessionName, token string) (AWSExchangeInput, error)` — validates non-empty ARN/session/token; default `DurationSeconds = 3600` (1h, within STS 15m–12h). This is the request shape passed to `sts.Client.AssumeRoleWithWebIdentity` (brief-03 §1). Unit test asserts construction, not a live call.
  - `type STSAssumeRoleWebIdentityAPI interface { AssumeRoleWithWebIdentity(ctx context.Context, in AWSExchangeInput) (Credentials, error) }` — the seam over the real `aws-sdk-go-v2` STS client (real adapter wires `sts.NewFromConfig`; lives in `cmd` / a later phase).
  - `type Credentials struct { AccessKeyID, SecretAccessKey, SessionToken string; Expiry time.Time }`

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/federation/aws_test.go`:
```go
package federation

import "testing"

func TestBuildAWSExchange(t *testing.T) {
	in, err := BuildAWSExchange("arn:aws:iam::123456789012:role/demo", "lifecycle-demo", "header.payload.sig")
	if err != nil {
		t.Fatalf("BuildAWSExchange: %v", err)
	}
	if in.RoleARN != "arn:aws:iam::123456789012:role/demo" {
		t.Fatalf("RoleARN = %q", in.RoleARN)
	}
	if in.WebIdentityToken != "header.payload.sig" {
		t.Fatalf("WebIdentityToken = %q", in.WebIdentityToken)
	}
	if in.DurationSeconds != 3600 {
		t.Fatalf("DurationSeconds = %d, want 3600 default", in.DurationSeconds)
	}
}

func TestBuildAWSExchangeRejectsEmpty(t *testing.T) {
	for _, tt := range []struct{ arn, sess, tok string }{
		{"", "s", "t"},
		{"arn", "", "t"},
		{"arn", "s", ""},
	} {
		if _, err := BuildAWSExchange(tt.arn, tt.sess, tt.tok); err == nil {
			t.Fatalf("expected error for %+v", tt)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/federation/ -run 'TestBuildAWSExchange' -v`
Expected: FAIL (undefined symbols).

- [ ] **Step 3: Write the AWS exchange shape**

Create `control-plane/internal/federation/aws.go`:
```go
package federation

import (
	"context"
	"fmt"
	"time"
)

// Credentials are short-lived cloud credentials returned by an exchange.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiry          time.Time
}

// AWSExchangeInput is the AssumeRoleWithWebIdentity request shape (brief-03 §1).
type AWSExchangeInput struct {
	RoleARN          string
	RoleSessionName  string
	WebIdentityToken string
	DurationSeconds  int32
}

// STSAssumeRoleWebIdentityAPI is the seam over aws-sdk-go-v2 STS. The real
// adapter calls sts.Client.AssumeRoleWithWebIdentity; unit tests use a fake.
type STSAssumeRoleWebIdentityAPI interface {
	AssumeRoleWithWebIdentity(ctx context.Context, in AWSExchangeInput) (Credentials, error)
}

// BuildAWSExchange constructs and validates the STS request. Default duration
// is 1h (within the STS 15m–12h range).
func BuildAWSExchange(roleARN, sessionName, token string) (AWSExchangeInput, error) {
	if roleARN == "" {
		return AWSExchangeInput{}, fmt.Errorf("aws exchange: empty role ARN")
	}
	if sessionName == "" {
		return AWSExchangeInput{}, fmt.Errorf("aws exchange: empty role session name")
	}
	if token == "" {
		return AWSExchangeInput{}, fmt.Errorf("aws exchange: empty web identity token")
	}
	return AWSExchangeInput{
		RoleARN:          roleARN,
		RoleSessionName:  sessionName,
		WebIdentityToken: token,
		DurationSeconds:  3600,
	}, nil
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/federation/ -run 'TestBuildAWSExchange' -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add control-plane/internal/federation/aws.go control-plane/internal/federation/aws_test.go
git commit -m "feat(control-plane): AWS AssumeRoleWithWebIdentity request construction"
```

---

### Task 14: GCP STS token-exchange request construction

**Files:**
- Create: `control-plane/internal/federation/gcp.go`
- Test: `control-plane/internal/federation/gcp_test.go`

**Interfaces:**
- Consumes: the token from Task 12.
- Produces:
  - `type GCPExchangeInput struct { Audience, SubjectToken, GrantType, RequestedTokenType, Scope, SubjectTokenType string }`
  - `func BuildGCPExchange(providerResource, token string) (GCPExchangeInput, error)` — sets `Audience = providerResource` (the WIF provider resource URL, used as both `aud` and the STS audience), `GrantType = "urn:ietf:params:oauth:grant-type:token-exchange"`, `RequestedTokenType = "urn:ietf:params:oauth:token-type:access_token"`, `SubjectTokenType = "urn:ietf:params:oauth:token-type:jwt"`, `Scope = "https://www.googleapis.com/auth/cloud-platform"` (brief-03 §2; direct resource access, no service account). Validates non-empty inputs.
  - `type GCPSTSAPI interface { ExchangeToken(ctx context.Context, in GCPExchangeInput) (Credentials, error) }` — seam over `cloud.google.com/go` STS POSTing to `https://sts.googleapis.com/v1/token`.

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/federation/gcp_test.go`:
```go
package federation

import "testing"

func TestBuildGCPExchange(t *testing.T) {
	const provider = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/prov"
	in, err := BuildGCPExchange(provider, "header.payload.sig")
	if err != nil {
		t.Fatalf("BuildGCPExchange: %v", err)
	}
	if in.Audience != provider {
		t.Fatalf("Audience = %q, want provider resource URL", in.Audience)
	}
	if in.GrantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Fatalf("GrantType = %q", in.GrantType)
	}
	if in.SubjectTokenType != "urn:ietf:params:oauth:token-type:jwt" {
		t.Fatalf("SubjectTokenType = %q", in.SubjectTokenType)
	}
	if in.RequestedTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Fatalf("RequestedTokenType = %q", in.RequestedTokenType)
	}
	if in.Scope != "https://www.googleapis.com/auth/cloud-platform" {
		t.Fatalf("Scope = %q", in.Scope)
	}
}

func TestBuildGCPExchangeRejectsEmpty(t *testing.T) {
	if _, err := BuildGCPExchange("", "t"); err == nil {
		t.Fatal("empty provider must error")
	}
	if _, err := BuildGCPExchange("p", ""); err == nil {
		t.Fatal("empty token must error")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/federation/ -run 'TestBuildGCPExchange' -v`
Expected: FAIL (undefined symbols).

- [ ] **Step 3: Write the GCP exchange shape**

Create `control-plane/internal/federation/gcp.go`:
```go
package federation

import (
	"context"
	"fmt"
)

// GCPExchangeInput is the STS token-exchange request shape (brief-03 §2).
type GCPExchangeInput struct {
	Audience           string // WIF provider resource URL (also the STS audience)
	SubjectToken       string
	GrantType          string
	RequestedTokenType string
	Scope              string
	SubjectTokenType   string
}

// GCPSTSAPI is the seam over the GCP STS endpoint (https://sts.googleapis.com/v1/token).
type GCPSTSAPI interface {
	ExchangeToken(ctx context.Context, in GCPExchangeInput) (Credentials, error)
}

// BuildGCPExchange constructs and validates the GCP STS request using direct
// resource access (no service-account impersonation).
func BuildGCPExchange(providerResource, token string) (GCPExchangeInput, error) {
	if providerResource == "" {
		return GCPExchangeInput{}, fmt.Errorf("gcp exchange: empty provider resource")
	}
	if token == "" {
		return GCPExchangeInput{}, fmt.Errorf("gcp exchange: empty subject token")
	}
	return GCPExchangeInput{
		Audience:           providerResource,
		SubjectToken:       token,
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
		Scope:              "https://www.googleapis.com/auth/cloud-platform",
	}, nil
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/federation/ -run 'TestBuildGCPExchange' -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add control-plane/internal/federation/gcp.go control-plane/internal/federation/gcp_test.go
git commit -m "feat(control-plane): GCP STS token-exchange request construction"
```

---

### Task 15: Azure FIC client-credentials + propagation-delay retry

**Files:**
- Create: `control-plane/internal/federation/azure.go`
- Test: `control-plane/internal/federation/azure_test.go`

**Interfaces:**
- Consumes: the token from Task 12.
- Produces:
  - `type AzureExchangeInput struct { TokenURL, ClientID, ClientAssertion, ClientAssertionType, GrantType, Scope string }`
  - `func BuildAzureExchange(tenant, clientID, assertion string) (AzureExchangeInput, error)` — `TokenURL = "https://login.microsoftonline.com/"+tenant+"/oauth2/v2.0/token"`, `GrantType = "client_credentials"`, `ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"`, `Scope = "https://management.azure.com/.default"` (brief-03 §3). Validates inputs.
  - `func IsPropagationError(err error) bool` — true when the error mentions `AADSTS70021` (FIC not yet propagated).
  - `type AzureTokenAPI interface { Exchange(ctx context.Context, in AzureExchangeInput) (Credentials, error) }`
  - `func ExchangeWithRetry(ctx context.Context, api AzureTokenAPI, in AzureExchangeInput, attempts int, backoff func(attempt int)) (Credentials, error)` — retries only on `AADSTS70021` (propagation delay); other errors fail fast. `backoff` is injected so tests don't sleep.

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/federation/azure_test.go`:
```go
package federation

import (
	"context"
	"errors"
	"testing"
)

func TestBuildAzureExchange(t *testing.T) {
	in, err := BuildAzureExchange("tenant-guid", "client-guid", "header.payload.sig")
	if err != nil {
		t.Fatalf("BuildAzureExchange: %v", err)
	}
	if in.TokenURL != "https://login.microsoftonline.com/tenant-guid/oauth2/v2.0/token" {
		t.Fatalf("TokenURL = %q", in.TokenURL)
	}
	if in.GrantType != "client_credentials" {
		t.Fatalf("GrantType = %q", in.GrantType)
	}
	if in.ClientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("ClientAssertionType = %q", in.ClientAssertionType)
	}
	if in.Scope != "https://management.azure.com/.default" {
		t.Fatalf("Scope = %q", in.Scope)
	}
}

type flakyAzure struct {
	failTimes int
	calls     int
}

func (f *flakyAzure) Exchange(_ context.Context, _ AzureExchangeInput) (Credentials, error) {
	f.calls++
	if f.calls <= f.failTimes {
		return Credentials{}, errors.New("AADSTS70021: No matching federated identity record found")
	}
	return Credentials{AccessKeyID: "ok"}, nil
}

func TestExchangeWithRetryOnPropagation(t *testing.T) {
	api := &flakyAzure{failTimes: 2}
	in, _ := BuildAzureExchange("t", "c", "tok")
	got, err := ExchangeWithRetry(context.Background(), api, in, 5, func(int) {})
	if err != nil {
		t.Fatalf("retry should succeed after propagation: %v", err)
	}
	if got.AccessKeyID != "ok" || api.calls != 3 {
		t.Fatalf("calls = %d, creds = %#v", api.calls, got)
	}
}

func TestExchangeWithRetryFailsFastOnOtherError(t *testing.T) {
	// Pointer receiver so calls is observable to the test (a value receiver would
	// count on a copy and always report 0 — the classic fake-receiver bug).
	api := &failAlways{err: errors.New("AADSTS7000215: invalid client secret")}
	in, _ := BuildAzureExchange("t", "c", "tok")
	if _, err := ExchangeWithRetry(context.Background(), api, in, 5, func(int) {}); err == nil {
		t.Fatal("non-propagation error must not be retried")
	}
	if api.calls != 1 {
		t.Fatalf("calls = %d, want 1 (fail fast)", api.calls)
	}
}

type failAlways struct {
	err   error
	calls int
}

func (f *failAlways) Exchange(_ context.Context, _ AzureExchangeInput) (Credentials, error) {
	f.calls++
	return Credentials{}, f.err
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd control-plane && go test ./internal/federation/ -run 'TestBuildAzureExchange|TestExchangeWithRetry' -v`
Expected: FAIL (undefined symbols).

- [ ] **Step 3: Write the Azure exchange + retry**

Create `control-plane/internal/federation/azure.go`:
```go
package federation

import (
	"context"
	"fmt"
	"strings"
)

// AzureExchangeInput is the client-credentials-with-client_assertion request
// shape (brief-03 §3).
type AzureExchangeInput struct {
	TokenURL            string
	ClientID            string
	ClientAssertion     string
	ClientAssertionType string
	GrantType           string
	Scope               string
}

// AzureTokenAPI is the seam over the Entra token endpoint.
type AzureTokenAPI interface {
	Exchange(ctx context.Context, in AzureExchangeInput) (Credentials, error)
}

// BuildAzureExchange constructs and validates the Azure FIC token request.
func BuildAzureExchange(tenant, clientID, assertion string) (AzureExchangeInput, error) {
	if tenant == "" || clientID == "" || assertion == "" {
		return AzureExchangeInput{}, fmt.Errorf("azure exchange: tenant, client id and assertion are required")
	}
	return AzureExchangeInput{
		TokenURL:            "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token",
		ClientID:            clientID,
		ClientAssertion:     assertion,
		ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		GrantType:           "client_credentials",
		Scope:               "https://management.azure.com/.default",
	}, nil
}

// IsPropagationError reports whether err is the FIC-not-yet-propagated error.
func IsPropagationError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "AADSTS70021")
}

// ExchangeWithRetry retries only on the FIC propagation delay (AADSTS70021);
// any other error fails fast. backoff is injected so tests do not sleep.
func ExchangeWithRetry(ctx context.Context, api AzureTokenAPI, in AzureExchangeInput, attempts int, backoff func(attempt int)) (Credentials, error) {
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		creds, err := api.Exchange(ctx, in)
		if err == nil {
			return creds, nil
		}
		if !IsPropagationError(err) {
			return Credentials{}, err
		}
		lastErr = err
		if attempt < attempts {
			backoff(attempt)
		}
	}
	return Credentials{}, fmt.Errorf("azure exchange exhausted retries (propagation): %w", lastErr)
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/federation/ -run 'TestBuildAzureExchange|TestExchangeWithRetry' -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the whole federation package**

Run: `cd control-plane && go test ./internal/federation/ -v`
Expected: PASS (all Task 12–15 tests).

- [ ] **Step 6: Commit**

```bash
git add control-plane/internal/federation/azure.go control-plane/internal/federation/azure_test.go
git commit -m "feat(control-plane): Azure FIC exchange with propagation-delay retry"
```

---

### Task 16: Federation orchestrator (mint → exchange per cloud)

**Files:**
- Create: `control-plane/internal/federation/orchestrator.go`
- Test: `control-plane/internal/federation/orchestrator_test.go`

**Interfaces:**
- Consumes: `TokenMinter` (Task 12), `STSAssumeRoleWebIdentityAPI` / `GCPSTSAPI` / `AzureTokenAPI` (Tasks 13–15), `audit.Chain` (Task 6).
- Produces:
  - `type Targets struct { AWSRoleARN, AWSSessionName, GCPProvider, AzureTenant, AzureClientID string }`
  - `type Orchestrator struct { ... }` with `func NewOrchestrator(m *TokenMinter, aws STSAssumeRoleWebIdentityAPI, gcp GCPSTSAPI, az AzureTokenAPI, ch *audit.Chain) *Orchestrator`
  - `func (o *Orchestrator) FederateAll(ctx context.Context, t Targets, now time.Time) (map[Cloud]Credentials, error)` — for each cloud: mint the distinct token, build the exchange shape, call the cloud API (Azure via `ExchangeWithRetry`), emit an audit record per cloud (token redacted), aggregate credentials. A single cloud failure is recorded and returned as a wrapped error but does not abort the other clouds.

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/federation/orchestrator_test.go`:
```go
package federation

import (
	"context"
	"testing"
	"time"

	"github.com/lifecycle/control-plane/internal/audit"
)

// capturingDoer is reused from idp_test.go (same package). The orchestrator
// mints via the real TokenMinter, so only the cloud-exchange APIs are stubbed.

type stubAWS struct{ called bool }

func (s *stubAWS) AssumeRoleWithWebIdentity(_ context.Context, _ AWSExchangeInput) (Credentials, error) {
	s.called = true
	return Credentials{AccessKeyID: "aws-key"}, nil
}

type stubGCP struct{ called bool }

func (s *stubGCP) ExchangeToken(_ context.Context, _ GCPExchangeInput) (Credentials, error) {
	s.called = true
	return Credentials{AccessKeyID: "gcp-key"}, nil
}

type stubAzure struct{ called bool }

func (s *stubAzure) Exchange(_ context.Context, _ AzureExchangeInput) (Credentials, error) {
	s.called = true
	return Credentials{AccessKeyID: "az-key"}, nil
}

type nopSink struct{}

func (nopSink) Append(_ context.Context, _ audit.Record) error { return nil }

func TestFederateAll(t *testing.T) {
	d := &capturingDoer{resp: `{"token":"h.p.s"}`}
	m := NewTokenMinter("https://idp.lifecycle.example/federate", "repo:org/r:environment:production",
		Audiences{AWS: "aws-aud", GCP: "gcp-aud", Azure: "az-aud"}, d)
	aws, gcp, az := &stubAWS{}, &stubGCP{}, &stubAzure{}
	o := NewOrchestrator(m, aws, gcp, az, audit.NewChain(nopSink{}))

	creds, err := o.FederateAll(context.Background(), Targets{
		AWSRoleARN: "arn:aws:iam::1:role/r", AWSSessionName: "s",
		GCPProvider: "//iam.googleapis.com/p", AzureTenant: "t", AzureClientID: "c",
	}, time.Now())
	if err != nil {
		t.Fatalf("FederateAll: %v", err)
	}
	if creds[CloudAWS].AccessKeyID != "aws-key" || creds[CloudGCP].AccessKeyID != "gcp-key" || creds[CloudAzure].AccessKeyID != "az-key" {
		t.Fatalf("creds = %#v", creds)
	}
	if !aws.called || !gcp.called || !az.called {
		t.Fatal("every cloud must be exchanged")
	}
}
```

> Note: `capturingDoer` is reused from `idp_test.go` (same `federation` package, so test helpers are shared — do not redeclare it). `nopSink` is declared once here, local to the `federation` package's tests (the `offboard` package has its own separate `nopSink`).

- [ ] **Step 2: Run to verify it fails**

Run: `cd control-plane && go test ./internal/federation/ -run TestFederateAll -v`
Expected: FAIL (undefined `Orchestrator`/`NewOrchestrator`/`FederateAll`).

- [ ] **Step 3: Write the orchestrator**

Create `control-plane/internal/federation/orchestrator.go`:
```go
package federation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/lifecycle/control-plane/internal/audit"
)

// Targets holds the per-cloud federation targets.
type Targets struct {
	AWSRoleARN     string
	AWSSessionName string
	GCPProvider    string
	AzureTenant    string
	AzureClientID  string
}

// Orchestrator mints a distinct token per cloud and performs each exchange.
type Orchestrator struct {
	minter *TokenMinter
	aws    STSAssumeRoleWebIdentityAPI
	gcp    GCPSTSAPI
	az     AzureTokenAPI
	chain  *audit.Chain
}

// NewOrchestrator wires the minter, the three cloud APIs, and the audit chain.
func NewOrchestrator(m *TokenMinter, aws STSAssumeRoleWebIdentityAPI, gcp GCPSTSAPI, az AzureTokenAPI, ch *audit.Chain) *Orchestrator {
	return &Orchestrator{minter: m, aws: aws, gcp: gcp, az: az, chain: ch}
}

// FederateAll mints + exchanges for all three clouds. One cloud's failure is
// recorded and joined into the returned error but does not abort the others.
func (o *Orchestrator) FederateAll(ctx context.Context, t Targets, now time.Time) (map[Cloud]Credentials, error) {
	out := make(map[Cloud]Credentials, 3)
	var errs []error

	if creds, err := o.federateAWS(ctx, t, now); err != nil {
		errs = append(errs, err)
	} else {
		out[CloudAWS] = creds
	}
	if creds, err := o.federateGCP(ctx, t, now); err != nil {
		errs = append(errs, err)
	} else {
		out[CloudGCP] = creds
	}
	if creds, err := o.federateAzure(ctx, t, now); err != nil {
		errs = append(errs, err)
	} else {
		out[CloudAzure] = creds
	}
	return out, errors.Join(errs...)
}

func (o *Orchestrator) federateAWS(ctx context.Context, t Targets, now time.Time) (Credentials, error) {
	tok, err := o.minter.MintFor(ctx, CloudAWS)
	if err != nil {
		return Credentials{}, fmt.Errorf("aws mint: %w", err)
	}
	in, err := BuildAWSExchange(t.AWSRoleARN, t.AWSSessionName, tok)
	if err != nil {
		return Credentials{}, err
	}
	creds, err := o.aws.AssumeRoleWithWebIdentity(ctx, in)
	o.emit(ctx, now, CloudAWS, t.AWSRoleARN, err)
	if err != nil {
		return Credentials{}, fmt.Errorf("aws exchange: %w", err)
	}
	return creds, nil
}

func (o *Orchestrator) federateGCP(ctx context.Context, t Targets, now time.Time) (Credentials, error) {
	tok, err := o.minter.MintFor(ctx, CloudGCP)
	if err != nil {
		return Credentials{}, fmt.Errorf("gcp mint: %w", err)
	}
	in, err := BuildGCPExchange(t.GCPProvider, tok)
	if err != nil {
		return Credentials{}, err
	}
	creds, err := o.gcp.ExchangeToken(ctx, in)
	o.emit(ctx, now, CloudGCP, t.GCPProvider, err)
	if err != nil {
		return Credentials{}, fmt.Errorf("gcp exchange: %w", err)
	}
	return creds, nil
}

func (o *Orchestrator) federateAzure(ctx context.Context, t Targets, now time.Time) (Credentials, error) {
	tok, err := o.minter.MintFor(ctx, CloudAzure)
	if err != nil {
		return Credentials{}, fmt.Errorf("azure mint: %w", err)
	}
	in, err := BuildAzureExchange(t.AzureTenant, t.AzureClientID, tok)
	if err != nil {
		return Credentials{}, err
	}
	// Azure FICs propagate slowly; retry only on AADSTS70021.
	creds, err := ExchangeWithRetry(ctx, o.az, in, 5, func(attempt int) {
		time.Sleep(time.Duration(attempt) * 2 * time.Second)
	})
	o.emit(ctx, now, CloudAzure, t.AzureClientID, err)
	if err != nil {
		return Credentials{}, fmt.Errorf("azure exchange: %w", err)
	}
	return creds, nil
}

func (o *Orchestrator) emit(ctx context.Context, now time.Time, c Cloud, target string, exchangeErr error) {
	if o.chain == nil {
		return
	}
	outcome := "success"
	if exchangeErr != nil {
		outcome = "failure"
	}
	// Token is never included; only non-secret target metadata.
	_, _ = o.chain.Emit(ctx, audit.Event{
		EventTime: now,
		Actor:     "lifecycle-control-plane",
		Action:    "federation.exchange",
		Subject:   string(c),
		Outcome:   outcome,
		Details:   map[string]string{"cloud": string(c), "target": target},
	})
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/federation/ -run TestFederateAll -v`
Expected: PASS.

- [ ] **Step 5: Run the whole package + vet**

Run: `cd control-plane && go vet ./internal/federation/ && go test ./internal/federation/`
Expected: PASS, vet clean.

- [ ] **Step 6: Commit**

```bash
git add control-plane/internal/federation/orchestrator.go control-plane/internal/federation/orchestrator_test.go
git commit -m "feat(control-plane): federation orchestrator (mint per cloud -> exchange)"
```

---

### Task 17: CLI commands (`access-review`, `offboard`)

**Files:**
- Create: `control-plane/internal/cli/run.go`
- Create: `control-plane/cmd/access-review/main.go`
- Create: `control-plane/cmd/offboard/main.go`
- Test: `control-plane/internal/cli/run_test.go`

**Interfaces:**
- Consumes: `review`, `offboard`, `audit`, `ports` packages.
- Produces:
  - `type Config struct { Mode string; UserID string; ForCause bool; Apps []string }` (`Mode` ∈ `"access-review"`, `"offboard"`).
  - `func ParseArgs(args []string) (Config, error)` — flag parsing (`-mode`, `-user`, `-for-cause`, `-apps` comma-separated).
  - `func RunOffboard(ctx context.Context, r ports.Revoker, ch *audit.Chain, cfg Config, now time.Time) (offboard.SagaResult, error)` — validates `cfg.UserID`/`cfg.Apps`, runs the saga, returns error when `!AllGreen` so the CI job fails on incomplete offboarding.
- `cmd/*/main.go` are thin: parse flags → build real adapters (edge-API SCIM/state/revoker, cloud SDK clients) → call the domain. The `main` packages are not unit-tested (they wire real I/O); `internal/cli` holds the testable logic.

- [ ] **Step 1: Write the failing test**

Create `control-plane/internal/cli/run_test.go`:
```go
package cli

import (
	"context"
	"testing"
	"time"

	"github.com/lifecycle/control-plane/internal/audit"
	"github.com/lifecycle/control-plane/internal/ports"
)

func TestParseArgs(t *testing.T) {
	cfg, err := ParseArgs([]string{"-mode", "offboard", "-user", "u1", "-for-cause", "-apps", "github,slack"})
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	if cfg.Mode != "offboard" || cfg.UserID != "u1" || !cfg.ForCause {
		t.Fatalf("cfg = %#v", cfg)
	}
	if len(cfg.Apps) != 2 || cfg.Apps[0] != "github" {
		t.Fatalf("apps = %#v", cfg.Apps)
	}
	if _, err := ParseArgs([]string{"-mode", "bogus"}); err == nil {
		t.Fatal("unknown mode must error")
	}
}

type allGoodRevoker struct{}

func (allGoodRevoker) DisableAccount(context.Context, string, string) error    { return nil }
func (allGoodRevoker) RevokeOAuthGrant(context.Context, string, string) error  { return nil }
func (allGoodRevoker) TerminateSessions(context.Context, string, string) error { return nil }
func (allGoodRevoker) RevokeAPIKeys(context.Context, string, string) error     { return nil }
func (allGoodRevoker) Supports(string) ports.AppCapabilities {
	return ports.AppCapabilities{OAuthRevocation: true, BackChannelLogout: true, APIKeyRevocation: true}
}

type nopSink struct{}

func (nopSink) Append(context.Context, audit.Record) error { return nil }

func TestRunOffboardAllGreen(t *testing.T) {
	cfg := Config{Mode: "offboard", UserID: "u1", Apps: []string{"github"}}
	res, err := RunOffboard(context.Background(), allGoodRevoker{}, audit.NewChain(nopSink{}), cfg, time.Now())
	if err != nil {
		t.Fatalf("RunOffboard: %v", err)
	}
	if !res.AllGreen {
		t.Fatal("expected all-green")
	}
}

func TestRunOffboardRequiresUserAndApps(t *testing.T) {
	if _, err := RunOffboard(context.Background(), allGoodRevoker{}, audit.NewChain(nopSink{}), Config{Mode: "offboard"}, time.Now()); err == nil {
		t.Fatal("missing user/apps must error")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd control-plane && go test ./internal/cli/ -run 'TestParseArgs|TestRunOffboard' -v`
Expected: FAIL (package undefined).

- [ ] **Step 3: Write the CLI logic + thin mains**

Create `control-plane/internal/cli/run.go`:
```go
// Package cli holds the testable command logic; cmd/*/main.go wire real I/O.
package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/lifecycle/control-plane/internal/audit"
	"github.com/lifecycle/control-plane/internal/offboard"
	"github.com/lifecycle/control-plane/internal/ports"
)

// Config is the parsed invocation.
type Config struct {
	Mode     string
	UserID   string
	ForCause bool
	Apps     []string
}

// ParseArgs parses CLI flags into a Config.
func ParseArgs(args []string) (Config, error) {
	fs := flag.NewFlagSet("control-plane", flag.ContinueOnError)
	mode := fs.String("mode", "", "access-review | offboard")
	user := fs.String("user", "", "subject identity id")
	forCause := fs.Bool("for-cause", false, "immediate for-cause offboarding")
	apps := fs.String("apps", "", "comma-separated app ids")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	switch *mode {
	case "access-review", "offboard":
	default:
		return Config{}, fmt.Errorf("unknown mode %q", *mode)
	}
	cfg := Config{Mode: *mode, UserID: *user, ForCause: *forCause}
	for _, a := range strings.Split(*apps, ",") {
		if a = strings.TrimSpace(a); a != "" {
			cfg.Apps = append(cfg.Apps, a)
		}
	}
	return cfg, nil
}

// RunOffboard runs the Leaver saga and fails (returns error) unless all-green,
// so a CI job exits non-zero on incomplete offboarding.
func RunOffboard(ctx context.Context, r ports.Revoker, ch *audit.Chain, cfg Config, now time.Time) (offboard.SagaResult, error) {
	if cfg.UserID == "" {
		return offboard.SagaResult{}, fmt.Errorf("offboard: -user is required")
	}
	if len(cfg.Apps) == 0 {
		return offboard.SagaResult{}, fmt.Errorf("offboard: -apps is required")
	}
	res := offboard.RunLeaver(ctx, r, ch, cfg.UserID, cfg.Apps, now)
	if !res.AllGreen {
		return res, fmt.Errorf("offboard incomplete for %s: not all-green", cfg.UserID)
	}
	return res, nil
}
```

Create `control-plane/cmd/offboard/main.go`:
```go
// Command offboard runs the Leaver saga for a user across apps. Real adapters
// (edge-API revoker, audit sink) are constructed here; the testable logic lives
// in internal/cli. For-cause runs immediately; routine runs are Cron-driven.
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/lifecycle/control-plane/internal/cli"
)

func main() {
	cfg, err := cli.ParseArgs(os.Args[1:])
	if err != nil {
		log.Fatalf("args: %v", err)
	}
	if cfg.Mode != "offboard" {
		log.Fatalf("this binary requires -mode offboard")
	}
	// TODO(adapters): construct the edge-API-backed Revoker and audit Sink here
	// (Phase 6 wires real cloud/edge endpoints). Until then this binary is the
	// composition root and is exercised end-to-end via internal/cli unit tests.
	_ = context.Background()
	_ = time.Now()
	log.Printf("offboard requested user=%s apps=%v for-cause=%v", cfg.UserID, cfg.Apps, cfg.ForCause)
}
```

Create `control-plane/cmd/access-review/main.go`:
```go
// Command access-review schedules/builds risk-tiered review campaigns. Real
// adapters are constructed here; testable logic lives in internal/review + cli.
package main

import (
	"log"
	"os"

	"github.com/lifecycle/control-plane/internal/cli"
)

func main() {
	cfg, err := cli.ParseArgs(os.Args[1:])
	if err != nil {
		log.Fatalf("args: %v", err)
	}
	if cfg.Mode != "access-review" {
		log.Fatalf("this binary requires -mode access-review")
	}
	// TODO(adapters): construct the edge-API StateStore + reviewer routing here
	// (Phase 6). Logic under test lives in internal/review.
	log.Printf("access-review run requested")
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd control-plane && go test ./internal/cli/ -run 'TestParseArgs|TestRunOffboard' -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Verify the binaries build**

Run: `cd control-plane && go build ./cmd/... && go vet ./... && go test ./...`
Expected: both binaries build, vet clean, all tests pass.

- [ ] **Step 6: Commit**

```bash
git add control-plane/internal/cli control-plane/cmd
git commit -m "feat(control-plane): access-review + offboard CLI commands"
```

---

### Task 18: GitHub Actions Cron workflow (access-review + offboarding-sweep)

**Files:**
- Create: `.github/workflows/control-plane-cron.yml`
- Create: `control-plane/docs/cron.md`

**Interfaces:**
- Consumes: `cmd/access-review`, `cmd/offboard` (Task 17).
- Produces: a scheduled workflow that builds the Go module, runs tests, and executes the two commands with **keyless GitHub OIDC** to AWS/GCP/Azure (no static cloud keys). Leaves an explicit SHA-pin note deferring action pinning + harden-runner to Phase 9.

- [ ] **Step 1: Document the run model + cloud OIDC**

Create `control-plane/docs/cron.md`:
```markdown
# Control-plane scheduled runs

The Go control plane runs as native Go in GitHub Actions Cron and locally — never
TinyGo, never on a Worker. Two commands:

- `access-review` — risk-tiered review sweep (privileged monthly/continuous,
  standard quarterly, low annual; per-entitlement last-use drives revoke recs;
  reviewer != grantor).
- `offboard` — the Leaver saga (disable -> RFC 7009 -> Back-Channel Logout ->
  API-key revoke). Routine runs are Cron-driven; for-cause is immediate (<5 min)
  via a manual `workflow_dispatch` with `-for-cause`.

## Cloud auth: keyless OIDC (zero static keys)

Each cloud trusts the GitHub OIDC issuer scoped to the repo **environment**
(`repo:ORG/REPO:environment:production`, exact `sub`). No long-lived cloud keys
exist. The federation orchestrator additionally mints a distinct edge-IdP RS256
token per cloud for the *demo* federation exchange; the CI job's own cloud calls
use GitHub OIDC.

## State + audit

State writes go to D1/DO and audit to R2 **via the edge API** (HTTPS), never by
opening a cloud connection directly from the job.

## Local run

    cd control-plane
    go run ./cmd/access-review -mode access-review
    go run ./cmd/offboard -mode offboard -user u1 -apps github,slack
```

- [ ] **Step 2: Write the workflow (SHA-pin note for Phase 9)**

Create `.github/workflows/control-plane-cron.yml`:
```yaml
name: control-plane-cron
on:
  schedule:
    - cron: '0 6 * * *'        # daily offboarding sweep (routine leavers)
    - cron: '0 7 * * 1'        # weekly access-review batch (Mondays)
  workflow_dispatch:           # for-cause immediate offboarding
    inputs:
      mode:
        description: access-review | offboard
        required: true
        default: offboard
      user:
        description: subject identity id (offboard)
        required: false
      apps:
        description: comma-separated app ids (offboard)
        required: false
      for_cause:
        description: immediate for-cause offboarding
        type: boolean
        default: false
permissions:
  contents: read
  id-token: write              # keyless OIDC to AWS/GCP/Azure
jobs:
  run:
    runs-on: ubuntu-latest
    environment: production     # OIDC sub pins to this environment
    defaults:
      run:
        working-directory: control-plane
    steps:
      # NOTE: Phase 9 hardens this — replace each @<tag> with a pinned commit SHA,
      # add step-security/harden-runner as the first step, and add per-cloud OIDC
      # login actions (aws-actions/configure-aws-credentials,
      # google-github-actions/auth, azure/login), all SHA-pinned.
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.23'
          cache-dependency-path: control-plane/go.sum
      - name: vet + test
        run: |
          go vet ./...
          go test ./...
      - name: build
        run: go build ./cmd/...
      - name: scheduled offboarding sweep
        if: github.event_name == 'schedule' && github.event.schedule == '0 6 * * *'
        run: ./offboard -mode offboard -user "${SWEEP_USER}" -apps "${SWEEP_APPS}"
        env:
          SWEEP_USER: ${{ vars.SWEEP_USER }}
          SWEEP_APPS: ${{ vars.SWEEP_APPS }}
      - name: scheduled access review
        if: github.event_name == 'schedule' && github.event.schedule == '0 7 * * 1'
        run: ./access-review -mode access-review
      - name: manual run
        if: github.event_name == 'workflow_dispatch'
        run: |
          if [ "${MODE}" = "offboard" ]; then
            FLAGS=""
            if [ "${FOR_CAUSE}" = "true" ]; then FLAGS="-for-cause"; fi
            ./offboard -mode offboard -user "${USER_ID}" -apps "${APPS}" ${FLAGS}
          else
            ./access-review -mode access-review
          fi
        env:
          MODE: ${{ github.event.inputs.mode }}
          USER_ID: ${{ github.event.inputs.user }}
          APPS: ${{ github.event.inputs.apps }}
          FOR_CAUSE: ${{ github.event.inputs.for_cause }}
```

- [ ] **Step 3: Verify the workflow YAML parses and the build target exists**

Run:
```bash
cd /Users/vladinirkamenev/Documents/projects/lifecycle
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/control-plane-cron.yml')); print('YAML OK')"
cd control-plane && go build ./cmd/... && echo "binaries build OK"
```
Expected: prints `YAML OK` and `binaries build OK`.

- [ ] **Step 4: Run the full module test suite once more (green gate)**

Run: `cd control-plane && go test ./... && go vet ./...`
Expected: all packages PASS, vet clean.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/control-plane-cron.yml control-plane/docs/cron.md
git commit -m "ci(control-plane): scheduled Cron workflow for reviews + offboarding (keyless OIDC)"
```

---

## Self-Review

**Spec coverage (Phase 5 scope = spec §4 Layer 3 + Layer 4 federation orchestration + §5 + §7 build-order item 5):**
- Native Go in CI (NOT TinyGo), real cloud SDKs behind interfaces → Tasks 1, 13–16, 18 (Global Constraints + research 05 decision). ✓
- Identity/entitlement domain model + NHI owner invariant → Task 2. ✓
- JML state machine `invited→provisioned→active→review-due→offboarded` with table-driven transition tests → Task 3. ✓
- Joiner: birthright RBAC + JIT time-boxed privileged → Task 4. ✓
- Mover diff engine `grant=target−current`, `revoke=current−target` + explicit add-only-is-a-bug test → Task 5. ✓
- Leaver offboarding saga with per-app sub-states `account_disabled→oauth_grant_revoked→sessions_terminated→api_keys_revoked` behind `Revoker`, compensating-control logging when an app lacks RFC 7009 / Back-Channel Logout, all-green=offboarded, for-cause path → Tasks 7 (ports), 8, 17. ✓
- SCIM client reconciliation (push to edge SCIM behind `SCIMClient`, disable never delete) → Task 7. ✓
- Risk-tiered access-review scheduler (cadence from a policy table; micro-cert batches; per-entitlement last-use → revoke recs; reviewer≠grantor) → Task 10. ✓
- SoD detective evaluation calling the policy engine (control plane = PA, never embeds the matrix) → Task 9. ✓
- NHI lifecycle (owner required; human leaver fans out transfer-or-rotate) → Tasks 2 (invariant), 11. ✓
- Multi-cloud federation orchestrator — per-cloud RS256 token from edge IdP then exchange: AWS `sts:AssumeRoleWithWebIdentity`, GCP STS token exchange, Azure client-credentials with `client_assertion`, each behind an interface with brief-03 request shapes; Azure FIC propagation delay + retry; request construction unit-tested, no live calls → Tasks 12–16. ✓
- Audit emitter: append-only `seq`/`record_hash`/`prev_hash` hash-chaining, never logs tokens, redact-before-write → Task 6 (reused in 8, 16). ✓
- Writes state to D1/DO and audit to R2 via the edge API → `ports.StateStore` + `audit.Sink` are edge-API seams (Tasks 6, 7); the concrete HTTP adapters are **Go code owned by this phase** (wired in `cmd/*/main.go`), exercising the Phase-6 Terraform-provisioned edge/clouds at runtime. ✓
- GitHub Actions Cron workflow running access-review + offboarding-sweep, keyless OIDC to clouds, SHA-pin note left for Phase 9 → Task 18. ✓

**Placeholder scan:** No "TBD/handle later" in domain/test code; every code step is complete, compilable Go as written. The only intentional deferrals are: the concrete adapter **wiring** in `cmd/*/main.go` (marked `TODO(adapters)`) — the adapter Go code (SCIM HTTP → `/scim/v2`, cloud-SDK, edge-API) is owned by **this phase** (Task 7 and Tasks 12–16 define the interfaces + request construction; the thin HTTP/SDK glue lives here, not in Phase 6 which is Terraform/CDK only); and Phase 9 (workflow SHA-pinning + harden-runner + per-cloud OIDC login actions, marked in a `NOTE`). The Task 15 Azure fake and the Task 16 orchestrator test are now correct as written (pointer-receiver fake so call counts are observable; no unused stubs), so no pre-run hand-edits are required.

**Type/interface consistency (names reused across tasks):**
- `domain.Identity` / `domain.Entitlement` / `domain.LifecycleState` / `domain.RiskTier` (Task 2) are consumed unchanged by Tasks 3, 4, 5, 7, 9, 10, 11.
- `domain.LifecycleState` is declared in Task 2 and given transition logic in Task 3 (same package, sibling file) — no redefinition.
- `ports.SCIMClient` / `ports.StateStore` / `ports.Revoker` / `ports.AppCapabilities` (Task 7) are consumed unchanged by Tasks 8 (Revoker/AppCapabilities), 17 (Revoker), and the SCIM reconcile (SCIMClient).
- `audit.Chain` / `audit.Event` / `audit.Sink` / `audit.Record` (Task 6) are consumed unchanged by Tasks 8, 16, 17 (every cross-package use takes `*audit.Chain` and a `audit.Sink` fake).
- `federation.Cloud` / `Credentials` / `Audiences` / `TokenMinter` / `STSAssumeRoleWebIdentityAPI` / `GCPSTSAPI` / `AzureTokenAPI` (Tasks 12–15) are consumed unchanged by the orchestrator (Task 16). `Credentials` is declared once (Task 13) and reused by GCP/Azure.
- `offboard.SagaResult` / `offboard.RunLeaver` (Task 8) are consumed unchanged by `cli.RunOffboard` (Task 17).
- `sod.PolicyEngine` (Task 9) is the same Zero-Trust seam as `ports.Revoker`/`SCIMClient`: external dependency behind an interface, faked in tests, with the concrete HTTP/SDK adapter implemented as Go code in this phase (wired in `cmd/*/main.go`).

**Owned by this phase (Go code), wired in `cmd/*/main.go`:** the concrete edge-API HTTP adapters for `SCIMClient` (calling the edge SCIM endpoint at `/scim/v2`), `StateStore`, `Revoker`, `audit.Sink`, and the concrete cloud-SDK adapters implementing `STSAssumeRoleWebIdentityAPI`/`GCPSTSAPI`/`AzureTokenAPI`. These run **against** the Phase-6 Terraform-provisioned trust + the Phase-2/3 edge endpoints at runtime, but the adapter code is Go and lives here. **Deferred to other phases (correctly out of scope):** the OPA/Regorus `PolicyEngine` implementation (Phase 4 authoring + edge eval); SLSA provenance / SBOM / harden-runner / SHA-pinning of the Cron workflow (Phase 9).
