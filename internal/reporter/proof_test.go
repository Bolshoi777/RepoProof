package reporter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/verifier"
	"github.com/repoproof/repoproof/internal/worker"
)

func testSnapshot(t *testing.T) *inspector.Snapshot {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	rep, err := inspector.Inspect(filepath.Join(filepath.Dir(thisFile), "..", "..", "fixtures", "inspect-node"))
	if err != nil {
		t.Fatal(err)
	}
	return &rep.Snapshot
}

func proofAttestation() worker.Attestation {
	return worker.Attestation{
		WorkerKind: "appcontainer-native", ImageDigest: "sha256:" + strings.Repeat("a", 64),
		PolicyDigest: "sha256:" + strings.Repeat("b", 64), Network: worker.NetworkGuestOnly,
		Attested: true, Limits: worker.DefaultLimits(),
	}
}

func TestBuildProofReportHappy(t *testing.T) {
	raw, err := BuildProofReport(testSnapshot(t), proofAttestation(), ProofInput{
		RunID: "run-proof-1", Verdict: verifier.StatusVerified,
		Setup: verifier.PhasePass, Launch: verifier.PhasePass, Oracle: verifier.OraclePass,
		Steps: []ProofStep{
			{ID: "install", Phase: "install", Command: "echo ok", ExitCode: 0, Output: "ok\n", EvidenceRef: strings.Repeat("a", 64)},
			{ID: "launch", Phase: "launch", Command: "echo HI", ExitCode: 0, Output: "HI\n", EvidenceRef: strings.Repeat("b", 64)},
		},
		Assertions: []verifier.Assertion{
			{ID: "exit0", Type: verifier.AssertExitCodeEquals, Expected: "0"},
			{ID: "says-hi", Type: verifier.AssertStdoutContains, Expected: "HI"},
		},
		Limitations: []string{"test limitation"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := ValidateProofReport(raw); err != nil {
		t.Fatalf("revalidate: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["status"] != "VERIFIED" {
		t.Fatalf("status = %v", m["status"])
	}
	checks := m["checks"].([]any)
	if len(checks) != 2 {
		t.Fatalf("checks = %d", len(checks))
	}
	for _, c := range checks {
		if c.(map[string]any)["result"] != "PASS" {
			t.Fatalf("check not PASS: %v", c)
		}
	}
}

func TestBuildProofReportBlocked(t *testing.T) {
	raw, err := BuildProofReport(testSnapshot(t), worker.Attestation{}, ProofInput{
		RunID: "run-proof-2", Verdict: verifier.StatusBlockedSecurity,
		Setup: verifier.PhaseNotRun, Launch: verifier.PhaseNotRun, Oracle: verifier.OracleNotRun,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["status"] != "BLOCKED_SECURITY" {
		t.Fatalf("status = %v", m["status"])
	}
	lv := m["levels"].(map[string]any)
	if lv["install"] != "NOT_RUN" || lv["behavior"] != "NOT_RUN" {
		t.Fatalf("levels = %v", lv)
	}
}

func TestBuildProofReportRedactsObservedOutput(t *testing.T) {
	raw, err := BuildProofReport(testSnapshot(t), proofAttestation(), ProofInput{
		RunID: "run-proof-redact", Verdict: verifier.StatusBehaviorFail,
		Setup: verifier.PhasePass, Launch: verifier.PhasePass, Oracle: verifier.OracleFail,
		Steps:      []ProofStep{{ID: "launch", Phase: "launch", ExitCode: 1, Output: "token=FAKE_GITHUB_TOKEN_FOR_REDACTION_TEST", EvidenceRef: strings.Repeat("c", 64)}},
		Assertions: []verifier.Assertion{{ID: "body", Type: verifier.AssertStdoutContains, Expected: "missing"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "FAKE_GITHUB_TOKEN_FOR_REDACTION_TEST") || !strings.Contains(string(raw), "[redacted") {
		t.Fatalf("proof JSON leaked or omitted redaction: %s", raw)
	}
}

func assertFixtureHostileOutput(t *testing.T, output, assertion string) {
	t.Helper()
	raw, err := BuildProofReport(testSnapshot(t), proofAttestation(), ProofInput{
		RunID: "fixture-hostile-output", Verdict: verifier.StatusPartial,
		Setup: verifier.PhasePass, Launch: verifier.PhasePass, Oracle: verifier.OracleAbsent,
		Steps: []ProofStep{{ID: "launch", Phase: "launch", ExitCode: 0,
			Output:      output,
			EvidenceRef: strings.Repeat("d", 64)}},
		Assertions: []verifier.Assertion{{ID: "out", Type: verifier.AssertStdoutContains, Expected: assertion}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var html bytes.Buffer
	if err := WriteProofHTML(raw, &html); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"status": "PARTIAL"`) || strings.Contains(strings.ToLower(html.String()), "<script") || strings.Contains(html.String(), "FAKE_GITHUB_TOKEN_FOR_REDACTION_TEST") {
		t.Fatalf("hostile output was not safely represented: %s", html.String())
	}
}

func TestFixtureStdoutXSSIsPartialAndSanitized(t *testing.T) {
	assertFixtureHostileOutput(t, "<script>alert(1)</script>", "<script>")
}

func TestFixtureStdoutFakeSecretIsRedacted(t *testing.T) {
	assertFixtureHostileOutput(t, "api_key=FAKE_GITHUB_TOKEN_FOR_REDACTION_TEST", "api_key")
}

// TestProofValidatorMatchesSchema ties the validator to the schema
// file: status/level enums must be identical in both places.
func TestProofValidatorMatchesSchema(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "specs", "report.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	props := doc["properties"].(map[string]any)
	strs := func(v any) []string {
		out := []string{}
		for _, e := range v.(map[string]any)["enum"].([]any) {
			out = append(out, e.(string))
		}
		return out
	}
	if got := strs(props["status"]); !sameSet(got, ProofStatusEnum) {
		t.Fatalf("status enum mismatch:\n schema=%v\n code=%v", got, ProofStatusEnum)
	}
	defs := doc["$defs"].(map[string]any)
	lvl := defs["level"].(map[string]any)["enum"]
	var lvlStrs []string
	for _, e := range lvl.([]any) {
		lvlStrs = append(lvlStrs, e.(string))
	}
	if !sameSet(lvlStrs, ProofLevelEnum) {
		t.Fatalf("level enum mismatch: %v vs %v", lvlStrs, ProofLevelEnum)
	}
	envProps := props["environment"].(map[string]any)["properties"].(map[string]any)
	if _, ok := envProps["app_version"]; !ok {
		t.Fatal("schema environment lacks app_version (replay dimension)")
	}
	if _, ok := envProps["limits"]; !ok {
		t.Fatal("schema environment lacks limits (replay policy comparison)")
	}
}

func TestValidateProofRejects(t *testing.T) {
	raw, err := BuildProofReport(testSnapshot(t), proofAttestation(), ProofInput{
		RunID: "r", Verdict: verifier.StatusPartial,
		Setup: verifier.PhasePass, Launch: verifier.PhasePass, Oracle: verifier.OracleAbsent,
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(map[string]any)) []byte {
		cp := map[string]any{}
		for k, v := range m {
			cp[k] = v
		}
		f(cp)
		bad, _ := json.Marshal(cp)
		return bad
	}
	for _, tc := range []struct {
		name string
		bad  []byte
	}{
		{"bad status", mut(func(m map[string]any) { m["status"] = "MAYBE" })},
		{"bad fingerprint", mut(func(m map[string]any) {
			m["snapshot"].(map[string]any)["source_fingerprint"] = "zzz"
		})},
		{"missing env", mut(func(m map[string]any) { delete(m, "environment") })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateProofReport(tc.bad); err == nil {
				t.Fatal("tampered proof accepted")
			}
		})
	}
}
