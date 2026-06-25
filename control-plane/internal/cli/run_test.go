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
