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
