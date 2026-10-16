package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/repoproof/repoproof/internal/sandbox"
)

func TestEnsurePythonCacheHit(t *testing.T) {
	cache := t.TempDir()
	rtDir := filepath.Join(cache, "py-3.13.16")
	bin := filepath.Join(rtDir, "python", "python.exe")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"kind":"python","exe":"python/python.exe","version":"3.13.16","files":1}`
	if err := os.WriteFile(filepath.Join(rtDir, "python.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rtDir, ".complete"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rt, root, err := EnsurePython(ctx, cache)
	if err != nil {
		t.Fatal(err)
	}
	if rt.Origin != sandbox.OriginPortable || rt.ExePath != bin {
		t.Fatalf("resolved = %+v", rt)
	}
	if root != rtDir {
		t.Fatalf("root = %q, want %q", root, rtDir)
	}
}

func TestEnsurePythonCacheMissNoNetwork(t *testing.T) {
	// Empty cache with a cancelled context: provisioning must fail
	// fast without network, never hang, never resolve phantom runtimes.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := EnsurePython(ctx, t.TempDir()); err == nil {
		t.Fatal("empty cache + cancelled ctx must fail")
	}
	// Corrupt manifest is skipped, not trusted.
	cache := t.TempDir()
	if err := os.WriteFile(filepath.Join(cache, "x.json"), []byte("{bad"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rt, _ := resolveCache(cache, sandbox.RuntimePython); rt.Origin != sandbox.OriginNone {
		t.Fatalf("corrupt cache trusted: %+v", rt)
	}
}

func TestStageWheelsAbsent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	staged, err := StageWheels(ctx, t.TempDir(), t.TempDir())
	if err != nil || staged != nil {
		t.Fatalf("no requirements must be (nil, nil): %v %v", staged, err)
	}
}

func TestStageWheelsRejectsRanges(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("six>=1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := StageWheels(ctx, dir, t.TempDir()); err == nil {
		t.Fatal("ranges must be refused")
	}
}

// TestIncompleteCacheSkipped proves the regression fix: a manifest
// without completion record (interrupted provision, like the real
// broken cache found on 2026-10-12) is skipped, never trusted.
func TestIncompleteCacheSkipped(t *testing.T) {
	cache := t.TempDir()
	rtDir := filepath.Join(cache, "py-broken")
	bin := filepath.Join(rtDir, "python", "python.exe")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"kind":"python","exe":"python/python.exe","version":"3.13.16","files":1}`
	if err := os.WriteFile(filepath.Join(rtDir, "python.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	// No .complete file: must be skipped despite valid manifest+exe.
	if rt, _ := resolveCache(cache, sandbox.RuntimePython); rt.Origin != sandbox.OriginNone {
		t.Fatalf("incomplete cache trusted: %+v", rt)
	}
	// Wrong file count must also fail.
	if err := os.WriteFile(filepath.Join(rtDir, ".complete"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rtDir, "extra.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rt, _ := resolveCache(cache, sandbox.RuntimePython); rt.Origin != sandbox.OriginNone {
		t.Fatalf("count-mismatched cache trusted: %+v", rt)
	}
}

func TestCopyDirRecursiveRejectsSymlinkEscape(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "dst")
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(src, "linked.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := copyDirRecursive(src, dst); err == nil {
		t.Fatal("copy must refuse symlink/reparse source")
	}
	if _, err := os.Stat(filepath.Join(dst, "linked.txt")); !os.IsNotExist(err) {
		t.Fatal("symlink target was copied")
	}
}

func TestFingerprintTreeDetectsRuntimeDrift(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "python.exe")
	if err := os.WriteFile(path, []byte("runtime-a"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := fingerprintTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("runtime-b"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := fingerprintTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("runtime drift was not detected")
	}
}
