//go:build windows

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceBytesCountsOwnedFilesWithoutFollowingLinks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "payload.bin"), []byte("123456"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.bin")
	if err := os.WriteFile(outside, []byte("outside-secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.bin")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	size, err := workspaceBytes(root)
	if err != nil {
		t.Fatal(err)
	}
	if size != 6 {
		t.Fatalf("workspace size=%d, want 6 (link target must not be followed)", size)
	}
}

func TestWorkspaceBudgetMonitorStopsOnGrowth(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "payload.bin"), make([]byte, 2*1024*1024), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	terminated := make(chan struct{}, 1)
	failures := make(chan error, 1)
	done := make(chan struct{})
	go watchWorkspaceBudget(ctx, root, 1, func() { terminated <- struct{}{} }, failures, done)
	select {
	case err := <-failures:
		if err == nil || !strings.Contains(err.Error(), "workspace disk budget exceeded") {
			t.Fatalf("unexpected budget error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("workspace budget monitor did not fire")
	}
	select {
	case <-terminated:
	case <-time.After(time.Second):
		t.Fatal("budget monitor did not request termination")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("budget monitor did not stop")
	}
}
