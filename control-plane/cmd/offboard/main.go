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
