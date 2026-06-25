// Package offboard runs the Leaver multi-step saga. active=false alone leaves
// live sessions/refresh tokens valid (research 02 #1), so each app runs, in
// order: disable -> revoke OAuth grant/refresh (RFC 7009) -> terminate sessions
// (Back-Channel Logout) -> revoke API keys. Only all-green = offboarded. When an
// app lacks a capability the step is skipped and a compensating control logged.
package offboard

import (
	"context"
	"time"

	"github.com/tessera/control-plane/internal/audit"
	"github.com/tessera/control-plane/internal/ports"
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
		{SubAccountDisabled, false, nil, func(ctx context.Context, r ports.Revoker, app, u string) error {
			return r.DisableAccount(ctx, app, u)
		}},
		{SubOAuthGrantRevoked, true, func(c ports.AppCapabilities) bool { return c.OAuthRevocation }, func(ctx context.Context, r ports.Revoker, app, u string) error {
			return r.RevokeOAuthGrant(ctx, app, u)
		}},
		{SubSessionsTerminated, true, func(c ports.AppCapabilities) bool { return c.BackChannelLogout }, func(ctx context.Context, r ports.Revoker, app, u string) error {
			return r.TerminateSessions(ctx, app, u)
		}},
		{SubAPIKeysRevoked, true, func(c ports.AppCapabilities) bool { return c.APIKeyRevocation }, func(ctx context.Context, r ports.Revoker, app, u string) error {
			return r.RevokeAPIKeys(ctx, app, u)
		}},
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
		Actor:     "tessera-control-plane",
		Action:    action,
		Subject:   userID,
		Outcome:   outcome,
		Details:   details,
	})
}
