//go:build windows

package sandbox

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/repoproof/repoproof/internal/pydeps"
	"github.com/repoproof/repoproof/internal/verifier"
)

// TestPipOfflineInstallLive is the online-install proof (G.7, python):
// the host stages a digest-pinned wheel from PyPI (allowlisted), the
// container installs with --no-index --find-links, and hooks (if any)
// execute only inside. No container egress is used at any point.
func TestPipOfflineInstallLive(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	prov := provisionPython(t, ctx)
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

	pins, err := pydeps.ParseRequirements([]byte("six==1.16.0\n"))
	if err != nil {
		t.Fatal(err)
	}
	wheels := filepath.Join(s.Workspace, "wheels")
	staged, err := pydeps.Stage(ctx, "", pins, wheels)
	if err != nil {
		t.Fatalf("stage (finding, network or PyPI?): %v", err)
	}
	if len(staged) != 1 {
		t.Fatalf("staged = %v", staged)
	}
	t.Logf("staged %s", staged[0])

	code, out, err := LaunchInJob(ctx, s, pyExe,
		[]string{"-m", "pip", "install", "--no-index", "--find-links", wheels, "six==1.16.0"},
		env, 5*time.Minute)
	if err != nil || code != 0 {
		t.Fatalf("offline pip install failed: code=%d err=%v out=%.500q", code, err, out)
	}

	code, out, err = LaunchInJob(ctx, s, pyExe,
		[]string{"-c", quotepy(`import six;print(six.__version__)`)}, env, 120*time.Second)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	obs := verifier.Observation{ExitCode: code, Stdout: out}
	ok, failed := verifier.Evaluate([]verifier.Assertion{
		{ID: "exit", Type: verifier.AssertExitCodeEquals, Expected: "0"},
		{ID: "ver", Type: verifier.AssertStdoutContains, Expected: "1.16.0"},
	}, obs)
	if !ok {
		t.Fatalf("assertions failed: %v (out=%.500q)", failed, out)
	}
	if got := verifier.Decide(verifier.Inputs{
		Setup: verifier.PhasePass, Launch: verifier.PhasePass,
		Oracle: verifier.OracleFromOutcome(ok),
	}); got != verifier.StatusVerified {
		t.Fatalf("pip chain = %q, want VERIFIED", got)
	}
}
