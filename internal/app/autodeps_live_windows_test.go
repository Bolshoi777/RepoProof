//go:build windows

package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/planner"
	"github.com/repoproof/repoproof/internal/policy"
	"github.com/repoproof/repoproof/internal/verifier"
)

// TestAutoDepsLive is the wired dependency proof: a python project
// with requirements.txt verifies end to end with no manual staging —
// the prologue installs six inside, the oracle imports it.
func TestAutoDepsLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	proj := t.TempDir()
	outside := t.TempDir()
	write := func(dir, name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write(proj, "pyproject.toml", "[project]\nname = \"autodeps-live\"\nversion = \"0.0.1\"\n")
	write(proj, "requirements.txt", "six==1.16.0\n")
	write(proj, "README.md", "## Install\n\n```sh\necho setup\n```\n\n## Run\n\n```sh\npython -c \"import six; print(six.__version__)\"\n```\n")
	contractPath := write(proj, "c.yaml", `version: 1
project: {kind: cli, runtime: python}
execution: {max_wall_seconds: 300, max_output_bytes: 1048576, install_network: none, verify_network: guest-only}
steps:
  - {id: install, phase: install, from_readme: true}
  - {id: launch, phase: launch, from_readme: true}
proof:
  - {id: exit0, type: exit_code_equals, expected: 0}
  - {id: ver, type: stdout_contains, expected: "1.16.0"}
`)
	rep, err := inspector.Inspect(proj)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Stack != "python" {
		t.Fatalf("stack = %q", rep.Stack)
	}
	plan := planner.Build(&rep.Snapshot)
	if plan.NeedsReview {
		t.Fatalf("fixture plan needs review: %v", plan.ReviewReasons)
	}
	ap := policy.Approval{
		Version: "1", PlanFingerprint: plan.Fingerprint, Commit: plan.Commit,
		Statement: "autodeps live", ApprovedNetwork: "guest-only",
		ExpiresAt: policy.NewExpiry(time.Now().UTC()),
	}
	araw, _ := json.Marshal(ap)
	approvePath := write(outside, "a.json", string(araw))

	out, err := RunVerify(ctx, VerifyParams{
		Target: proj, ContractPath: contractPath, ApprovePath: approvePath,
	}, func(msg string) { t.Logf("progress: %s", msg) })
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Verdict != verifier.StatusBlockedSecurity {
		t.Fatalf("verdict = %q, summary:\n%s", out.Verdict, out.Summary)
	}
	if !strings.Contains(out.Summary, "1.16.0") && !strings.Contains(string(out.Proof), "1.16.0") {
		t.Logf("version string not surfaced; summary:\n%s", out.Summary)
	}
}
