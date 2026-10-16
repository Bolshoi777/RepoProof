package reporter

import (
	"strings"
	"testing"

	"github.com/repoproof/repoproof/internal/verifier"
)

func hostileProof(t *testing.T) []byte {
	t.Helper()
	snap := testSnapshot(t)
	att := proofAttestation()
	raw, err := BuildProofReport(snap, att, ProofInput{
		RunID: "hostile-1", Verdict: verifier.StatusBehaviorFail,
		Setup: verifier.PhasePass, Launch: verifier.PhasePass, Oracle: verifier.OracleFail,
		Steps: []ProofStep{
			{ID: "x", Phase: "launch", Command: `echo <img src=x onerror=alert(1)>`, ExitCode: 0,
				Output: "access_token=FAKE_GITHUB_TOKEN_FOR_REDACTION_TEST", EvidenceRef: strings.Repeat("c", 64)},
		},
		Assertions: []verifier.Assertion{
			{ID: "o", Type: verifier.AssertStdoutContains, Expected: "expected"},
		},
		Limitations: []string{"note <script>alert(2)</script> here"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestProofHTMLNeutralizesHostile(t *testing.T) {
	var sb strings.Builder
	if err := WriteProofHTML(hostileProof(t), &sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, bad := range []string{"<script", "<img src=x", "FAKE_GITHUB_TOKEN_FOR_REDACTION_TEST"} {
		if strings.Contains(out, bad) {
			t.Fatalf("HTML leaked %q", bad)
		}
	}
	for _, want := range []string{"&lt;script&gt;", "&lt;img", "[redacted", "BEHAVIOR_FAIL"} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
}

func TestProofHTMLSelfContained(t *testing.T) {
	var sb strings.Builder
	if err := WriteProofHTML(hostileProof(t), &sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	if !strings.HasPrefix(out, "<!DOCTYPE html>") {
		t.Fatal("missing doctype")
	}
	for _, forbidden := range []string{"<script", "src=\"http", "href=\"http", "<link"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("active/external content: %q", forbidden)
		}
	}
	for _, want := range []string{"show-install", "show-launch", "show-verify", "show-system", "phase-launch"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing static timeline filter %q", want)
		}
	}
}

func TestProofHTMLRejectsInvalid(t *testing.T) {
	var sb strings.Builder
	if err := WriteProofHTML([]byte(`{"status":"MAYBE"}`), &sb); err == nil {
		t.Fatal("invalid report must be refused")
	}
}
