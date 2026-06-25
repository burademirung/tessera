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
