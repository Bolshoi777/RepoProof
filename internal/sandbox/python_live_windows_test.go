//go:build windows

package sandbox

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/repoproof/repoproof/internal/verifier"
)

// TestPythonGoldenLive provisions pinned portable CPython, stages it
// into the session workspace, and runs the happy + broken contract
// pair inside the AppContainer.
func TestPythonGoldenLive(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	start := time.Now()
	prov := provisionPython(t, ctx)
	t.Logf("provisioned %s in %v", prov.Runtime.Version, time.Since(start))

	sessions := t.TempDir()
	s, err := Prepare(ctx, sessions, n2run(t), DefaultJobLimits(), nil)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer func() { _ = Finalize(&s) }()

	rtDir := filepath.Join(s.Workspace, "rt")
	copyDir(t, prov.Root, rtDir)
	pyExe := filepath.Join(rtDir, filepath.FromSlash(PinnedPython().ExeRelPath))
	env := SanitizeEnv(s.Workspace, []string{filepath.Dir(pyExe)}, nil)

	run := func(script, expect string) verifier.Oracle {
		// Quote the -c payload for the C-runtime split: the joined
		// command line is re-parsed, so inner quotes need escaping.
		quoted := "\"" + strings.ReplaceAll(script, "\"", "\\\"") + "\""
		code, out, err := LaunchInJob(ctx, s, pyExe,
			[]string{"-c", quoted}, env, 120*time.Second)
		if err != nil {
			t.Fatalf("launch: %v", err)
		}
		ok, failed := verifier.Evaluate([]verifier.Assertion{
			{ID: "exit", Type: verifier.AssertExitCodeEquals, Expected: "0"},
			{ID: "out", Type: verifier.AssertStdoutContains, Expected: expect},
		}, verifier.Observation{ExitCode: code, Stdout: out})
		if !ok {
			head := out
			if len(head) > 2000 {
				head = head[:2000]
			}
			t.Logf("assertions failed: %v (out=%.2000q)", failed, head)
		}
		return verifier.OracleFromOutcome(ok)
	}

	happy := verifier.Decide(verifier.Inputs{
		Setup: verifier.PhasePass, Launch: verifier.PhasePass,
		Oracle: run(`print("HELLO_PY")`, "HELLO_PY"),
	})
	if happy != verifier.StatusVerified {
		t.Fatalf("python happy = %q, want VERIFIED", happy)
	}

	broken := verifier.Decide(verifier.Inputs{
		Setup: verifier.PhasePass, Launch: verifier.PhasePass,
		Oracle: run(`print("WRONG")`, "HELLO_PY"),
	})
	if broken != verifier.StatusBehaviorFail {
		t.Fatalf("python broken = %q, want BEHAVIOR_FAIL", broken)
	}
}
