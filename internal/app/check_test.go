package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/repoproof/repoproof/internal/verifier"
)

// TestCheckRequiresConfirmation: no flag, no run. Portable: returns
// before any session or store exists.
func TestCheckRequiresConfirmation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var progress []string
	out, err := CheckTarget(ctx, CheckParams{Target: "../../fixtures/inspect-node"},
		func(msg string) { progress = append(progress, msg) })
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if out.ExitCode != 11 || out.Verdict != verifier.StatusInconclusive {
		t.Fatalf("code=%d verdict=%q", out.ExitCode, out.Verdict)
	}
	if len(progress) == 0 {
		t.Fatal("plan must be printed for review even without confirmation")
	}
}

// TestCheckUnsupportedWithoutRunning: out-of-scope stack verdicts
// without creating sessions, portably.
func TestCheckUnsupportedWithoutRunning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := CheckTarget(ctx, CheckParams{
		Target: "../../fixtures/unsupported-rust", ConfirmRun: true,
	}, nil)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if out.ExitCode != 12 || out.Verdict != verifier.StatusUnsupported {
		t.Fatalf("code=%d verdict=%q summary=%q", out.ExitCode, out.Verdict, out.Summary)
	}
	if !strings.Contains(out.Summary, "out of scope") {
		t.Fatalf("summary must explain: %q", out.Summary)
	}
}
