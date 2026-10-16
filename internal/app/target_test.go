package app

import (
	"context"
	"testing"
)

// TestResolveTargetLocalPassthrough keeps local targets byte-identical:
// no copy, no network, cleanup is a no-op.
func TestResolveTargetLocalPassthrough(t *testing.T) {
	dir := t.TempDir()
	got, cleanup, err := resolveTarget(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got != dir {
		t.Fatalf("local target rewritten: %q != %q", got, dir)
	}
}

// TestResolveTargetRejectsBadURL proves URL validation happens before any
// network: non-GitHub hosts, credentials, and malformed owner/repo forms
// fail offline (ValidateURL precedes ls-remote/clone).
func TestResolveTargetRejectsBadURL(t *testing.T) {
	for _, raw := range []string{
		"https://gitlab.com/o/r",
		"https://user:token@github.com/o/r",
		"https://github.com/o",
		"https://github.com/o/r/tree/main",
		// NOTE: non-https inputs are local paths by design (they fail
		// later at inspect lstat); only https:// enters URL handling.
	} {
		if _, _, err := resolveTarget(context.Background(), raw); err == nil {
			t.Fatalf("bad URL accepted: %q", raw)
		}
	}
}
