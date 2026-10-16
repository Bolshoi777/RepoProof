package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolvePortable(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "py", "python.exe")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"kind":"python","exe":"py/python.exe","version":"3.13-test","files":1}`
	if err := os.WriteFile(filepath.Join(root, "python.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".complete"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rt := Resolve(ctx, RuntimePython, []string{root}, nil, false)
	if rt.Origin != OriginPortable || rt.ExePath != bin || rt.Version != "3.13-test" {
		t.Fatalf("resolved = %+v", rt)
	}
}

func TestResolveAbsent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rt := Resolve(ctx, RuntimeNode, []string{t.TempDir()}, []string{t.TempDir()}, true)
	if rt.Origin != OriginNone || rt.ExePath != "" {
		t.Fatalf("absent must resolve to none: %+v", rt)
	}
}

func TestResolveBadManifest(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "node.json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if rt := Resolve(ctx, RuntimeNode, []string{root}, nil, false); rt.Origin != OriginNone {
		t.Fatalf("broken manifest must not resolve: %+v", rt)
	}
}
