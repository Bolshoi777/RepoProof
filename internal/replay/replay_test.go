package replay

import (
	"strings"
	"testing"

	"github.com/repoproof/repoproof/internal/worker"
)

func testAttestation() worker.Attestation {
	return worker.Attestation{
		WorkerKind:   "appcontainer",
		ImageDigest:  "sha256:" + strings.Repeat("a", 64),
		PolicyDigest: "sha256:" + strings.Repeat("b", 64),
		Network:      worker.NetworkGuestOnly,
		Attested:     true,
		Limits:       worker.DefaultLimits(),
	}
}

func TestIdenticalReplays(t *testing.T) {
	rec := Capture(testAttestation(), "22621", map[string]string{"python": "3.13.16"})
	digest, err := rec.Digest()
	if err != nil {
		t.Fatal(err)
	}
	cur := Capture(testAttestation(), "22621", map[string]string{"python": "3.13.16"})
	ok, warnings, err := CheckReplay(rec, digest, cur)
	if err != nil || !ok || len(warnings) != 0 {
		t.Fatalf("identical env refused: ok=%v warnings=%v err=%v", ok, warnings, err)
	}
	// Digest determinism across recomputation.
	d2, err := rec.Digest()
	if err != nil || d2 != digest {
		t.Fatal("fingerprint digest unstable")
	}
}

func TestEachMismatchWarns(t *testing.T) {
	base := Capture(testAttestation(), "22621", map[string]string{"python": "3.13.16"})
	digest, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	mk := func(mut func(*Fingerprint)) Fingerprint {
		cp := base
		mut(&cp)
		return cp
	}
	cases := []struct {
		name    string
		current Fingerprint
		want    string
	}{
		{"image", mk(func(f *Fingerprint) { f.ImageDigest = "sha256:img2" }), "image_digest changed"},
		{"policy", mk(func(f *Fingerprint) { f.PolicyDigest = "sha256:pol2" }), "policy_digest changed"},
		{"worker", mk(func(f *Fingerprint) { f.WorkerKind = "vm" }), "worker_kind changed"},
		{"network", mk(func(f *Fingerprint) { f.Network = "restricted-install" }), "network_mode changed"},
		{"osbuild", mk(func(f *Fingerprint) { f.OSBuild = "99999" }), "os_build changed"},
		{"runtime", mk(func(f *Fingerprint) { f.Runtimes = map[string]string{"python": "3.12.0"} }), `runtime "python" changed`},
		{"runtime added", mk(func(f *Fingerprint) {
			f.Runtimes = map[string]string{"python": "3.13.16", "node": "22.18.0"}
		}), `runtime "node" changed`},
		{"app", mk(func(f *Fingerprint) { f.AppVersion = "9.9.9" }), "app_version changed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, warnings, err := CheckReplay(base, digest, tc.current)
			if err != nil {
				t.Fatalf("mismatch must warn, not error: %v", err)
			}
			if ok {
				t.Fatal("changed environment accepted for replay")
			}
			joined := strings.Join(warnings, "\n")
			if !strings.Contains(joined, tc.want) || !strings.Contains(joined, "re-verification required") {
				t.Fatalf("warnings %q missing %q", joined, tc.want)
			}
		})
	}
}

func TestTamperedDigestErrors(t *testing.T) {
	rec := Capture(testAttestation(), "22621", nil)
	cur := Capture(testAttestation(), "22621", nil)
	ok, _, err := CheckReplay(rec, strings.Repeat("0", 64), cur)
	if err == nil || ok {
		t.Fatalf("tampered digest must error: ok=%v err=%v", ok, err)
	}
}

func TestCaptureRecordsOnlyProvided(t *testing.T) {
	f := Capture(testAttestation(), "", nil)
	if f.OS == "" || f.Arch == "" || f.AppVersion == "" {
		t.Fatalf("machine fields must be filled: %+v", f)
	}
	if len(f.Runtimes) != 0 {
		t.Fatalf("unmeasured runtimes must stay empty: %+v", f.Runtimes)
	}
}
