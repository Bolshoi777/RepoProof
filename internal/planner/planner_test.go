package planner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/repoproof/repoproof/internal/inspector"
)

func inspectFixture(t *testing.T, name string) *inspector.Snapshot {
	t.Helper()
	rep, err := inspector.Inspect(filepath.Join("..", "..", "fixtures", name))
	if err != nil {
		t.Fatalf("inspect %s: %v", name, err)
	}
	return &rep.Snapshot
}

// mkProject builds a synthetic supported project in a temp dir.
func mkProject(t *testing.T, readme string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := inspector.Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Stack != inspector.StackNode {
		t.Fatalf("stack = %q", rep.Stack)
	}
	return dir
}

func inspectDir(t *testing.T, dir string) *inspector.Snapshot {
	t.Helper()
	rep, err := inspector.Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &rep.Snapshot
}

func TestCleanPlanIsAutoApprovable(t *testing.T) {
	dir := mkProject(t, "## Install\n\n```sh\nnpm install\n```\n\n## Run\n\n```sh\nnpm start\n```\n")
	p := Build(inspectDir(t, dir))
	if p.NeedsReview || !p.AutoApprovable {
		t.Fatalf("clean plan needs review: %v", p.ReviewReasons)
	}
	if len(p.Steps) != 2 {
		t.Fatalf("steps = %d", len(p.Steps))
	}
	s0 := p.Steps[0]
	if s0.ID != "readme-1" || s0.Phase != "install" || s0.Command != "npm install" {
		t.Fatalf("step0 = %+v", s0)
	}
	if s0.CWD != "." || !s0.RequiresApproval {
		t.Fatalf("step0 cwd/approval wrong: %+v", s0)
	}
	if s0.TimeoutSeconds != TimeoutInstall || s0.Network != NetworkPossible {
		t.Fatalf("step0 timeout/network wrong: %+v", s0)
	}
	if s0.Origin.LineStart != 4 || s0.Origin.SourceFile != "README.md" {
		t.Fatalf("step0 origin wrong: %+v", s0.Origin)
	}
	s1 := p.Steps[1]
	if s1.Phase != "launch" || s1.TimeoutSeconds != TimeoutLaunch || s1.Network != NetworkNone {
		t.Fatalf("step1 = %+v", s1)
	}
	if p.Fingerprint == "" || p.Version != "1" {
		t.Fatalf("plan identity wrong: %+v", p)
	}
}

func TestEnvPlaceholdersFlagReview(t *testing.T) {
	dir := mkProject(t, "```sh\nPORT=$PORT npm start --dir %APPDATA%\\x\n```\n")
	p := Build(inspectDir(t, dir))
	if !p.NeedsReview || p.AutoApprovable {
		t.Fatal("env placeholders must force review")
	}
	got := p.Steps[0].EnvPlaceholders
	if len(got) != 2 || got[0] != "APPDATA" || got[1] != "PORT" {
		t.Fatalf("placeholders = %v", got)
	}
	if !strings.Contains(strings.Join(p.ReviewReasons, ";"), "PORT") {
		t.Fatalf("reasons = %v", p.ReviewReasons)
	}
}

func TestUnclosedFenceFlagsReview(t *testing.T) {
	p := Build(inspectFixture(t, "readme-case"))
	if !p.NeedsReview {
		t.Fatal("unclosed fence must force review")
	}
	if !strings.Contains(strings.Join(p.ReviewReasons, ";"), "unclosed") {
		t.Fatalf("reasons = %v", p.ReviewReasons)
	}
}

func TestUnsupportedStackFlagsReview(t *testing.T) {
	p := Build(inspectFixture(t, "unsupported-rust"))
	if !p.NeedsReview || len(p.Steps) != 0 {
		t.Fatalf("rust plan: review=%v steps=%d", p.NeedsReview, len(p.Steps))
	}
	if !strings.Contains(strings.Join(p.ReviewReasons, ";"), "not v1-supported") {
		t.Fatalf("reasons = %v", p.ReviewReasons)
	}
}

func TestNoCommandsFlagsReview(t *testing.T) {
	p := Build(inspectFixture(t, "inspect-node"))
	if !p.NeedsReview {
		t.Fatal("command-less project must force review")
	}
	if !strings.Contains(strings.Join(p.ReviewReasons, ";"), "no commands") {
		t.Fatalf("reasons = %v", p.ReviewReasons)
	}
}

// TestHostilePlanStaysData proves the planner keeps a destructive README
// command as reviewable data with approval required, never an instruction.
func TestHostilePlanStaysData(t *testing.T) {
	p := Build(inspectFixture(t, "inspect-hostile"))
	if len(p.Steps) != 1 {
		t.Fatalf("steps = %+v", p.Steps)
	}
	if !strings.Contains(p.Steps[0].Command, "rm -rf") {
		t.Fatalf("hostile command lost: %+v", p.Steps[0])
	}
	if !p.Steps[0].RequiresApproval {
		t.Fatal("hostile step must require approval")
	}
}

func TestTimeoutDefaults(t *testing.T) {
	for phase, want := range map[string]int{
		"install": TimeoutInstall, "launch": TimeoutLaunch,
		"verify": TimeoutVerify, "unknown": TimeoutUnknown, "": TimeoutUnknown,
	} {
		if got := timeoutFor(phase); got != want {
			t.Fatalf("timeoutFor(%q) = %d, want %d", phase, got, want)
		}
	}
}
