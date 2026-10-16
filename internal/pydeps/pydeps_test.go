package pydeps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseRequirements(t *testing.T) {
	pins, err := ParseRequirements([]byte("# comment\n\nsix==1.16.0\r\nrequests==2.31.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 2 || pins[0].Name != "six" || pins[1].Version != "2.31.0" {
		t.Fatalf("pins = %+v", pins)
	}
	for _, bad := range []string{
		"", "# only comments\n",
		"six>=1.0\n", "six\n", "-r other.txt\n", "--index-url x\n",
		"pkg @ https://x/y.zip\n", "six==1.0; python_version>'3'\n",
	} {
		if _, err := ParseRequirements([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// fakePyPI serves metadata + file bytes for one pinned wheel.
func fakePyPI(t *testing.T, body string) (*httptest.Server, string) {
	t.Helper()
	var srv *httptest.Server
	sum := sha256.Sum256([]byte(body))
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/json") {
			meta := map[string]any{"urls": []any{map[string]any{
				"filename":    "six-1.16.0-py2.py3-none-any.whl",
				"url":         srv.URL + "/f/six.whl",
				"packagetype": "bdist_wheel",
				"digests":     map[string]any{"sha256": hex.EncodeToString(sum[:])},
			}}}
			raw, _ := json.Marshal(meta)
			w.Write(raw)
			return
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, hex.EncodeToString(sum[:])
}

func TestStageHappy(t *testing.T) {
	srv, _ := fakePyPI(t, "wheel-bytes")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	staged, err := Stage(ctx, srv.URL, []Pin{{Name: "six", Version: "1.16.0"}}, t.TempDir())
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if len(staged) != 1 || !strings.HasSuffix(staged[0], ".whl") {
		t.Fatalf("staged = %v", staged)
	}
	raw, err := os.ReadFile(staged[0])
	if err != nil || string(raw) != "wheel-bytes" {
		t.Fatalf("content wrong: %q %v", raw, err)
	}
}

func TestResolvedFingerprintBindsSelectedArtifact(t *testing.T) {
	srv, digest := fakePyPI(t, "wheel-bytes")
	got, err := ResolvedFingerprint(context.Background(), srv.URL, []Pin{{Name: "Six", Version: "1.16.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if got == "" || got == digest {
		t.Fatalf("resolved fingerprint must be a distinct aggregate digest: %q", got)
	}
	again, err := ResolvedFingerprint(context.Background(), srv.URL, []Pin{{Name: "Six", Version: "1.16.0"}})
	if err != nil || got != again {
		t.Fatalf("resolved fingerprint is not deterministic: %q %q %v", got, again, err)
	}
}

func TestStageNoWheel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"urls":[]}`))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := Stage(ctx, srv.URL, []Pin{{Name: "x", Version: "1"}}, t.TempDir()); err == nil {
		t.Fatal("empty file list must fail")
	}
}
