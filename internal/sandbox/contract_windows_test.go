//go:build windows

package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/repoproof/repoproof/internal/verifier"
)

// TestContractCmdGolden is the first proof-of-chain (N3): stage nothing
// untrusted, run inside the AppContainer, evaluate assertions on the
// recorded output, and decide. exit 0 plus the right output VERIFIES;
// the verdict comes from evidence, never from the exit code alone.
func TestContractCmdGolden(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sessions := t.TempDir()

	s, err := Prepare(ctx, sessions, n2run(t), DefaultJobLimits(), nil)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer func() { _ = Finalize(&s) }()
	env := SanitizeEnv(s.Workspace, nil, nil)

	code, out, err := LaunchInJob(ctx, s, `C:\Windows\System32\cmd.exe`,
		[]string{"/c", "echo HELLO_N3"}, env, 60*time.Second)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	obs := verifier.Observation{ExitCode: code, Stdout: out}
	ok, failed := verifier.Evaluate([]verifier.Assertion{
		{ID: "exit", Type: verifier.AssertExitCodeEquals, Expected: "0"},
		{ID: "out", Type: verifier.AssertStdoutContains, Expected: "HELLO_N3"},
	}, obs)
	if !ok {
		t.Fatalf("golden assertions failed: %v (out=%q)", failed, out)
	}
	got := verifier.Decide(verifier.Inputs{
		Setup: verifier.PhasePass, Launch: verifier.PhasePass,
		Oracle: verifier.OracleFromOutcome(ok),
	})
	if got != verifier.StatusVerified {
		t.Fatalf("golden chain = %q, want VERIFIED", got)
	}
}

// TestContractBrokenFails is the negative golden: exit 0 with the
// wrong output must end in BEHAVIOR_FAIL, never VERIFIED.
func TestContractBrokenFails(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sessions := t.TempDir()

	s, err := Prepare(ctx, sessions, n2run(t), DefaultJobLimits(), nil)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer func() { _ = Finalize(&s) }()
	env := SanitizeEnv(s.Workspace, nil, nil)

	code, out, err := LaunchInJob(ctx, s, `C:\Windows\System32\cmd.exe`,
		[]string{"/c", "echo WRONG_OUTPUT"}, env, 60*time.Second)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	obs := verifier.Observation{ExitCode: code, Stdout: out}
	ok, _ := verifier.Evaluate([]verifier.Assertion{
		{ID: "exit", Type: verifier.AssertExitCodeEquals, Expected: "0"},
		{ID: "out", Type: verifier.AssertStdoutContains, Expected: "HELLO_N3"},
	}, obs)
	if ok {
		t.Fatal("broken output must fail assertions")
	}
	got := verifier.Decide(verifier.Inputs{
		Setup: verifier.PhasePass, Launch: verifier.PhasePass,
		Oracle: verifier.OracleFromOutcome(ok),
	})
	if got != verifier.StatusBehaviorFail {
		t.Fatalf("broken chain = %q, want BEHAVIOR_FAIL", got)
	}
	if !strings.Contains(out, "WRONG_OUTPUT") {
		t.Fatalf("unexpected output %q", out)
	}
}
