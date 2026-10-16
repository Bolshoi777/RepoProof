//go:build windows

package orchestrate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/repoproof/repoproof/internal/contract"
	"github.com/repoproof/repoproof/internal/evidence"
	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/planner"
	"github.com/repoproof/repoproof/internal/sandbox"
	"github.com/repoproof/repoproof/internal/verifier"
)

// TestChainLive runs the full chain with a real AppContainer session
// and fake trust at the attestation layer: session, launches, evidence
// and verdict are real; the worker attestation is a test value because
// no backend exists yet. It proves chain mechanics, not backend trust.
func TestChainLive(t *testing.T) {
	if rep := sandbox.ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	proj := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(proj, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"name":"chain-live"}`)
	write("README.md", "## Install\n\n```sh\necho SETUP_LIVE\n```\n\n## Run\n\n```sh\necho HELLO_LIVE\n```\n")

	rep, err := inspector.Inspect(proj)
	if err != nil {
		t.Fatal(err)
	}
	plan := planner.Build(&rep.Snapshot)
	if plan.NeedsReview {
		t.Fatalf("fixture plan needs review: %v", plan.ReviewReasons)
	}
	// Contract bound to this plan: from_readme steps resolve in order.
	contractDoc := `version: 1
project: {kind: cli, runtime: node}
execution: {max_wall_seconds: 120, max_output_bytes: 65536, install_network: none, verify_network: guest-only}
steps:
  - {id: install, phase: install, from_readme: true}
  - {id: launch, phase: launch, from_readme: true}
proof:
  - {id: exit0, type: exit_code_equals, expected: 0}
  - {id: says-hi, type: stdout_contains, expected: "HELLO_LIVE"}
`
	cc, err := contract.Parse([]byte(contractDoc))
	if err != nil {
		t.Fatal(err)
	}
	store, err := evidence.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		RunID: "chain-live-1", SessionsDir: t.TempDir(),
		Plan: plan, Contract: cc,
		Approval:    testApproval(plan),
		Attestation: testAttestation(),
		Limits:      sandbox.DefaultJobLimits(),
		Store:       store,
		Prepare: func(ctx context.Context, sessionsDir, runID string) (sandbox.Session, error) {
			return sandbox.Prepare(ctx, sessionsDir, runID, sandbox.DefaultJobLimits(), nil)
		},
		Launch: func(ctx context.Context, s sandbox.Session, exe string, argv []string, env []string, timeout time.Duration) (int, string, error) {
			return sandbox.LaunchInJob(ctx, s, exe, argv, env, timeout)
		},
		Finalize: func(s *sandbox.Session) error { return sandbox.Finalize(s) },
	}
	res := Execute(ctx, cfg)
	if res.Verdict != verifier.StatusVerified {
		t.Fatalf("live chain = %q reasons=%v", res.Verdict, res.Reasons)
	}
	if !res.EvidenceOK {
		t.Fatal("evidence not sealed/verified")
	}
	for _, want := range []string{"SETUP_LIVE", "HELLO_LIVE"} {
		found := false
		for _, s := range res.Steps {
			if strings.Contains(s.Output, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("output %q missing from steps", want)
		}
	}
}
