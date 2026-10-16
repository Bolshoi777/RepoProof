//go:build windows

package app

import (
	"context"
	"strings"
	"testing"

	"github.com/repoproof/repoproof/internal/planner"
)

// TestAutoDepsURLLikeTargetIsGone documents the DEBT-020 boundary: raw URL
// strings must never reach autoDeps (resolveTarget materializes first).
// On Windows a URL-shaped path is a syntax error (not IsNotExist), so the
// old plumbing failed loudly here; the point is the error shape (hard
// fail), never a silent stage or skip.
func TestAutoDepsURLLikeTargetIsGone(t *testing.T) {
	p := VerifyParams{Target: "https://github.com/o/r"}
	plan := &planner.Plan{Stack: "python"}
	if _, err := autoDeps(context.Background(), p, plan); err == nil {
		t.Fatal("URL-shaped target must fail, not stage or skip")
	} else if !strings.Contains(err.Error(), "deps:") {
		t.Fatalf("wrong error shape: %v", err)
	}
}
