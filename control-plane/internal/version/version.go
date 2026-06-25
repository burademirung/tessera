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
