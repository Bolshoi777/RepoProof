package sandbox

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// copyDir recursively copies src into dst. Test helper for staging
// provisioned runtimes into session workspaces (Minimal Disk: the
// workspace is removed by Finalize).
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		s, d := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		if e.IsDir() {
			copyDir(t, s, d)
			continue
		}
		if err := copyFile(t, s, d); err != nil {
			t.Fatal(err)
		}
	}
}

func copyFile(t *testing.T, src, dst string) error {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// provisionPython fetches the pinned runtime into a temp cache.
func provisionPython(t *testing.T, ctx context.Context) ProvisionResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	prov, err := Provision(ctx, PinnedPython(), t.TempDir())
	if err != nil {
		t.Fatalf("provision failed: %v", err)
	}
	return prov
}
