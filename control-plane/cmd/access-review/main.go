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
