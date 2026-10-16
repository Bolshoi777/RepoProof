package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/reporter"
	"github.com/repoproof/repoproof/internal/sandbox"
	"github.com/repoproof/repoproof/internal/verifier"
)

// TestInspectParityWithCore is the G4 gate foundation: the service
// layer (which the GUI will call) returns byte-identical validated
// JSON to what the CLI path produces from the same Core.
func TestInspectParityWithCore(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fix := filepath.Join(filepath.Dir(thisFile), "..", "..", "fixtures", "readme-case")

	viaService, err := Inspect(fix)
	if err != nil {
		t.Fatalf("service inspect: %v", err)
	}
	rep, err := inspector.Inspect(fix)
	if err != nil {
		t.Fatal(err)
	}
	viaCore, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(viaService) != string(append(viaCore, '\n')) {
		t.Fatal("service inspect JSON differs from Core output")
	}
	var m map[string]any
	if err := json.Unmarshal(viaService, &m); err != nil {
		t.Fatal(err)
	}
	if m["stack"] != "unknown" {
		t.Fatalf("stack = %v", m["stack"])
	}
}

// TestBuildPlanParity checks the plan service path.
func TestBuildPlanParity(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fix := filepath.Join(filepath.Dir(thisFile), "..", "..", "fixtures", "readme-case")
	raw, err := BuildPlan(fix)
	if err != nil {
		t.Fatalf("service plan: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["needs_review"] != true {
		t.Fatalf("plan = %v, want needs_review", m)
	}
}

// TestReplayUnattestedIsNotReusable keeps replay fail-closed until the
// native security lab receipt is available.
func TestReplayUnattestedIsNotReusable(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fix := filepath.Join(filepath.Dir(thisFile), "..", "..", "fixtures", "inspect-node")
	rep, err := inspector.Inspect(fix)
	if err != nil {
		t.Fatal(err)
	}
	att := sandbox.NativeAttestation(sandbox.DefaultResourceLimits())
	proof, err := reporter.BuildProofReport(&rep.Snapshot, att, reporter.ProofInput{
		RunID: "replay-test-1", Verdict: verifier.StatusVerified,
		Setup: verifier.PhasePass, Launch: verifier.PhasePass, Oracle: verifier.OraclePass,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, proof, 0o644); err != nil {
		t.Fatal(err)
	}
	summary, code, err := ReplayReport(path)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if code != 11 || !strings.Contains(summary, "STALE") {
		t.Fatalf("code=%d summary:\n%s", code, summary)
	}
}

// TestReplayStaleOnEnvChange rewrites the image digest and requires
// STALE with exit 11 and a named warning.
func TestReplayStaleOnEnvChange(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fix := filepath.Join(filepath.Dir(thisFile), "..", "..", "fixtures", "inspect-node")
	rep, err := inspector.Inspect(fix)
	if err != nil {
		t.Fatal(err)
	}
	att := sandbox.NativeAttestation(sandbox.DefaultResourceLimits())
	att.Attested = true // synthetic receipt for fingerprint-difference test
	proof, err := reporter.BuildProofReport(&rep.Snapshot, att, reporter.ProofInput{
		RunID: "replay-test-2", Verdict: verifier.StatusVerified,
		Setup: verifier.PhasePass, Launch: verifier.PhasePass, Oracle: verifier.OraclePass,
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(proof, &m); err != nil {
		t.Fatal(err)
	}
	m["environment"].(map[string]any)["image_digest"] = "sha256:changed"
	raw, _ := json.Marshal(m)
	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	summary, code, err := ReplayReport(path)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if code != 11 || !strings.Contains(summary, "image_digest changed") {
		t.Fatalf("code=%d summary:\n%s", code, summary)
	}
}

// TestReplayBadFile requires a hard error for garbage input.
func TestReplayBadFile(t *testing.T) {
	if _, _, err := ReplayReport(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing file must error")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReplayReport(bad); err == nil {
		t.Fatal("garbage must error")
	}
}

// TestExitCodeForFinal pins the ADR-009 exit table: every verdict has
// exactly one code, and unknown inputs fail closed (internal error).
func TestExitCodeForFinal(t *testing.T) {
	cases := map[verifier.Status]int{
		verifier.StatusVerified:        0,
		verifier.StatusBehaviorFail:    10,
		verifier.StatusLaunchFail:      10,
		verifier.StatusInstallFail:     10,
		verifier.StatusDocsFail:        10,
		verifier.StatusPartial:         11,
		verifier.StatusInconclusive:    11,
		verifier.StatusUnsupported:     12,
		verifier.StatusBlockedSecurity: 13,
		verifier.StatusBlockedEnv:      14,
		verifier.StatusCancelled:       130,
		verifier.StatusErrorInternal:   20,
		"MADE_UP":                      20,
		"":                             20,
	}
	for verdict, want := range cases {
		if got := ExitCodeFor(verdict); got != want {
			t.Fatalf("ExitCodeFor(%q) = %d, want %d", verdict, got, want)
		}
	}
}

func TestReplayRejectsUnattestedVerifiedReport(t *testing.T) {
	rep, err := inspector.Inspect(filepath.Join("..", "..", "fixtures", "inspect-node"))
	if err != nil {
		t.Fatal(err)
	}
	att := sandbox.NativeAttestation(sandbox.DefaultResourceLimits())
	att.Attested = false
	raw, err := reporter.BuildProofReport(&rep.Snapshot, att, reporter.ProofInput{
		RunID: "replay-unattested", Verdict: verifier.StatusVerified,
		Setup: verifier.PhasePass, Launch: verifier.PhasePass, Oracle: verifier.OraclePass,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "unattested.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, code, err := ReplayReport(path)
	if err != nil || code != 11 {
		t.Fatalf("unattested VERIFIED replay: code=%d err=%v", code, err)
	}
}
