package offboard

import (
	"context"
	"testing"
	"time"

	"github.com/lifecycle/control-plane/internal/audit"
	"github.com/lifecycle/control-plane/internal/ports"
)

type fakeRevoker struct {
	caps   map[string]ports.AppCapabilities
	calls  []string
	failOn string // "app:step" to force an error
}

func (f *fakeRevoker) rec(app, step string) error {
	key := app + ":" + step
	f.calls = append(f.calls, key)
	if key == f.failOn {
		return errStep
	}
	return nil
}
func (f *fakeRevoker) DisableAccount(_ context.Context, app, _ string) error {
	return f.rec(app, "disable")
}
func (f *fakeRevoker) RevokeOAuthGrant(_ context.Context, app, _ string) error {
	return f.rec(app, "oauth")
}
func (f *fakeRevoker) TerminateSessions(_ context.Context, app, _ string) error {
	return f.rec(app, "sessions")
}
func (f *fakeRevoker) RevokeAPIKeys(_ context.Context, app, _ string) error {
	return f.rec(app, "apikeys")
}
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
