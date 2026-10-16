package sandbox

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func mkZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func serveZip(t *testing.T, raw []byte) (*httptest.Server, string) {
	t.Helper()
	sum := sha256.Sum256(raw)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(raw)
	}))
	t.Cleanup(srv.Close)
	return srv, hex.EncodeToString(sum[:])
}

func ctxTest(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestProvisionHappy(t *testing.T) {
	raw := mkZip(t, map[string]string{"node-v22/bin/node.exe": "fake-exe"})
	srv, sum := serveZip(t, raw)
	spec := FetchSpec{Kind: RuntimeNode, URL: srv.URL + "/n.zip", SHA256: sum,
		MaxBytes: 1 << 20, ExeRelPath: "node-v22/bin/node.exe", Version: "22-test"}
	res, err := Provision(ctxTest(t), spec, t.TempDir())
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if res.Runtime.Origin != OriginPortable || res.Runtime.Version != "22-test" {
		t.Fatalf("runtime = %+v", res.Runtime)
	}
}

func TestProvisionDigestMismatchCleansUp(t *testing.T) {
	raw := mkZip(t, map[string]string{"a": "b"})
	srv, _ := serveZip(t, raw)
	cache := t.TempDir()
	spec := FetchSpec{Kind: RuntimeNode, URL: srv.URL + "/n.zip",
		SHA256: strings.Repeat("0", 64), MaxBytes: 1 << 20, ExeRelPath: "a", Version: "x"}
	if _, err := Provision(ctxTest(t), spec, cache); err == nil {
		t.Fatal("digest mismatch must fail")
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("partial data left behind: %v", entries)
	}
}

func TestProvisionRejects(t *testing.T) {
	raw := mkZip(t, map[string]string{"a": "b"})
	srv, sum := serveZip(t, raw)
	evil := mkZip(t, map[string]string{"../evil.txt": "x"})
	evilSrv, evilSum := serveZip(t, evil)
	abs := mkZip(t, map[string]string{"/abs.txt": "x"})
	absSrv, absSum := serveZip(t, abs)
	cases := []struct {
		name string
		spec FetchSpec
	}{
		{"http remote", FetchSpec{Kind: RuntimeNode, URL: "http://example.com/n.zip", SHA256: sum, MaxBytes: 1 << 20, ExeRelPath: "a"}},
		{"no digest", FetchSpec{Kind: RuntimeNode, URL: srv.URL + "/n.zip", SHA256: "", MaxBytes: 1 << 20, ExeRelPath: "a"}},
		{"no cap", FetchSpec{Kind: RuntimeNode, URL: srv.URL + "/n.zip", SHA256: sum, ExeRelPath: "a"}},
		{"bad kind", FetchSpec{Kind: "rust", URL: srv.URL + "/n.zip", SHA256: sum, MaxBytes: 1 << 20, ExeRelPath: "a"}},
		{"oversize", FetchSpec{Kind: RuntimeNode, URL: srv.URL + "/n.zip", SHA256: sum, MaxBytes: 1, ExeRelPath: "a"}},
		{"traversal", FetchSpec{Kind: RuntimeNode, URL: evilSrv.URL + "/e.zip", SHA256: evilSum, MaxBytes: 1 << 20, ExeRelPath: "x", Version: "e"}},
		{"absolute", FetchSpec{Kind: RuntimeNode, URL: absSrv.URL + "/a.zip", SHA256: absSum, MaxBytes: 1 << 20, ExeRelPath: "x", Version: "a"}},
		{"missing exe", FetchSpec{Kind: RuntimeNode, URL: srv.URL + "/n.zip", SHA256: sum, MaxBytes: 1 << 20, ExeRelPath: "nope.exe", Version: "m"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Provision(ctxTest(t), tc.spec, t.TempDir()); err == nil {
				t.Fatal("expected refusal")
			}
		})
	}
}

func TestProvisionRejectsExecutableTraversal(t *testing.T) {
	for _, rel := range []string{"../outside.exe", "a/../../outside.exe", `/absolute.exe`, `a\\outside.exe`} {
		t.Run(rel, func(t *testing.T) {
			spec := FetchSpec{Kind: RuntimeNode, URL: "https://registry.example.test/node.zip", SHA256: strings.Repeat("a", 64), MaxBytes: 1 << 20, ExeRelPath: rel}
			if err := spec.validate(); err == nil {
				t.Fatalf("unsafe executable path accepted: %q", rel)
			}
		})
	}
}

func mkTarGz(t *testing.T, files map[string]string, links map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range links {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestProvisionTarGz(t *testing.T) {
	raw := mkTarGz(t, map[string]string{"py/python.exe": "fake"}, nil)
	srv, sum := serveZip(t, raw)
	spec := FetchSpec{Kind: RuntimePython, URL: srv.URL + "/p.tar.gz", SHA256: sum,
		MaxBytes: 1 << 20, ExeRelPath: "py/python.exe", Version: "3.13-test"}
	res, err := Provision(ctxTest(t), spec, t.TempDir())
	if err != nil {
		t.Fatalf("tar.gz provision: %v", err)
	}
	if res.Runtime.Origin != OriginPortable {
		t.Fatalf("runtime = %+v", res.Runtime)
	}
}

func TestProvisionTarGzRejects(t *testing.T) {
	mk := func(files map[string]string, links map[string]string) (string, string) {
		raw := mkTarGz(t, files, links)
		srv, sum := serveZip(t, raw)
		return srv.URL + "/p.tar.gz", sum
	}
	evilURL, evilSum := mk(map[string]string{"../evil": "x"}, nil)
	linkURL, linkSum := mk(map[string]string{}, map[string]string{"link": "target"})
	badGz := bytes.Repeat([]byte{0x1f, 0x8b, 0x00}, 100)
	badSrv, badSum := serveZip(t, badGz)
	cases := []struct {
		name string
		spec FetchSpec
	}{
		{"traversal", FetchSpec{Kind: RuntimePython, URL: evilURL, SHA256: evilSum, MaxBytes: 1 << 20, ExeRelPath: "x", Version: "e"}},
		{"symlink", FetchSpec{Kind: RuntimePython, URL: linkURL, SHA256: linkSum, MaxBytes: 1 << 20, ExeRelPath: "x", Version: "l"}},
		{"bad gzip", FetchSpec{Kind: RuntimePython, URL: badSrv.URL + "/b.tar.gz", SHA256: badSum, MaxBytes: 1 << 20, ExeRelPath: "x", Version: "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Provision(ctxTest(t), tc.spec, t.TempDir()); err == nil {
				t.Fatal("expected refusal")
			}
		})
	}
}
