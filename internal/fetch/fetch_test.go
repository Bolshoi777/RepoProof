package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func serve(t *testing.T, body string) (*httptest.Server, string) {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, hex.EncodeToString(sum[:])
}

func TestFetchHappy(t *testing.T) {
	srv, sum := serve(t, "fake-tarball-bytes")
	got, err := Fetch(testCtx(t), Spec{URL: srv.URL + "/a.tgz", SHA256: sum, MaxBytes: 1 << 20, Filename: "a.tgz"}, t.TempDir())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	raw, err := os.ReadFile(got)
	if err != nil || string(raw) != "fake-tarball-bytes" {
		t.Fatalf("content wrong: %q %v", raw, err)
	}
	if filepath.Base(got) != "a.tgz" {
		t.Fatalf("path = %q", got)
	}
}

func TestFetchRejects(t *testing.T) {
	srv, sum := serve(t, "x")
	_ = srv
	cases := []struct {
		name string
		spec Spec
	}{
		{"remote http", Spec{URL: "http://example.com/a", SHA256: sum, MaxBytes: 1, Filename: "a"}},
		{"https off-allowlist", Spec{URL: "https://example.com/a", SHA256: sum, MaxBytes: 1 << 20, Filename: "a"}},
		{"https evil subdomain", Spec{URL: "https://registry.npmjs.org.evil.com/a", SHA256: sum, MaxBytes: 1 << 20, Filename: "a"}},
		{"no digest", Spec{URL: "https://registry.npmjs.org/a", MaxBytes: 1 << 20, Filename: "a"}},
		{"bad digest", Spec{URL: "https://registry.npmjs.org/a", SHA256: "zz", MaxBytes: 1 << 20, Filename: "a"}},
		{"no cap", Spec{URL: "https://registry.npmjs.org/a", SHA256: sum, Filename: "a"}},
		{"path traversal", Spec{URL: "https://registry.npmjs.org/a", SHA256: sum, MaxBytes: 1 << 20, Filename: "../evil"}},
		{"abs path", Spec{URL: "https://registry.npmjs.org/a", SHA256: sum, MaxBytes: 1 << 20, Filename: "/abs"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Fetch(testCtx(t), tc.spec, t.TempDir()); err == nil {
				t.Fatal("expected refusal without network")
			}
		})
	}
}

func TestFetchDigestMismatch(t *testing.T) {
	srv, _ := serve(t, "real-bytes")
	spec := Spec{URL: srv.URL + "/a.tgz", SHA256: strings.Repeat("0", 64), MaxBytes: 1 << 20, Filename: "a.tgz"}
	dir := t.TempDir()
	if _, err := Fetch(testCtx(t), spec, dir); err == nil {
		t.Fatal("digest mismatch must fail")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("partial file left behind")
	}
}
