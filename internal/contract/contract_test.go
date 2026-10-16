package contract

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/repoproof/repoproof/internal/planner"
)

func exampleBytes(t *testing.T) []byte {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "specs", "repoproof.example.yaml"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	return raw
}

func TestExampleContractParses(t *testing.T) {
	c, err := Parse(exampleBytes(t))
	if err != nil {
		t.Fatalf("example contract rejected: %v", err)
	}
	if got := c.StepIDs(); len(got) != 2 || got[0] != "install" || got[1] != "launch" {
		t.Fatalf("steps = %v", got)
	}
	asserts := c.Assertions()
	if len(asserts) != 2 || asserts[0].Expected != "200" || asserts[1].Expected != "ok" {
		t.Fatalf("assertions = %+v", asserts)
	}
}

func TestRejectsTable(t *testing.T) {
	base := string(exampleBytes(t))
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"bad yaml", "version: [1,\n", "bad yaml"},
		{"unknown field", base + "\nzzz_top: 1\n", "bad yaml"},
		{"bad version", strings.Replace(base, "version: 1", "version: 2", 1), "version must be 1"},
		{"bad kind", strings.Replace(base, "kind: http", "kind: mobile", 1), "project.kind"},
		{"bad runtime", strings.Replace(base, "runtime: node", "runtime: rust", 1), "project.runtime"},
		{"wall zero", strings.Replace(base, "max_wall_seconds: 600", "max_wall_seconds: 0", 1), "max_wall_seconds"},
		{"wall huge", strings.Replace(base, "max_wall_seconds: 600", "max_wall_seconds: 9999", 1), "max_wall_seconds"},
		{"verify net", strings.Replace(base, "verify_network: guest-only", "verify_network: restricted", 1), "guest-only"},
		{"dup step", strings.Replace(base, "- id: launch", "- id: install", 1), "duplicate step id"},
		{"bad phase", strings.Replace(base, "phase: launch", "phase: orbit", 1), "phase must be"},
		{"remote target", strings.Replace(base, "http://127.0.0.1:8080/health", "https://example.com/health", 2), "http URL"},
		{"lan target", strings.Replace(base, "http://127.0.0.1:8080/health", "http://192.168.1.5/x", 2), "loopback"},
		{"bad type", strings.Replace(base, "type: http_status", "type: tcp_open", 1), "unknown type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q missing %q", err, tc.want)
			}
		})
	}
}

func TestProofMandatory(t *testing.T) {
	base := string(exampleBytes(t))
	idx := strings.Index(base, "\nproof:")
	if idx < 0 {
		t.Fatal("example has no proof block")
	}
	_, err := Parse([]byte(base[:idx] + "\nproof: []\n"))
	if err == nil || !strings.Contains(err.Error(), "proof assertion required") {
		t.Fatalf("empty proof must be rejected, got %v", err)
	}
}

func TestInlineRunVsFromReadme(t *testing.T) {
	valid := `version: 1
project: {kind: cli, runtime: node}
execution: {max_wall_seconds: 60, max_output_bytes: 1000, install_network: none, verify_network: guest-only}
steps:
  - {id: s1, phase: install, run: "npm install"}
proof:
  - {id: p1, type: exit_code_equals, expected: 0}
`
	if _, err := Parse([]byte(valid)); err != nil {
		t.Fatalf("inline run rejected: %v", err)
	}
	ambiguous := `version: 1
project: {kind: cli, runtime: node}
execution: {max_wall_seconds: 60, max_output_bytes: 1000, install_network: none, verify_network: guest-only}
steps:
  - {id: s1, phase: install, run: "npm install", from_readme: true}
proof:
  - {id: p1, type: exit_code_equals, expected: 0}
`
	if _, err := Parse([]byte(ambiguous)); err == nil {
		t.Fatal("run + from_readme together must be rejected")
	}
	emptyInline := `version: 1
project: {kind: cli, runtime: node}
execution: {max_wall_seconds: 60, max_output_bytes: 1000, install_network: none, verify_network: guest-only}
steps:
  - {id: s1, phase: install}
proof:
  - {id: p1, type: exit_code_equals, expected: 0}
`
	if _, err := Parse([]byte(emptyInline)); err == nil {
		t.Fatal("step with neither run nor from_readme must be rejected")
	}
}

func TestHermeticSteps(t *testing.T) {
	doc := `version: 1
project: {kind: cli, runtime: node}
execution: {max_wall_seconds: 60, max_output_bytes: 1000, install_network: none, verify_network: guest-only}
steps:
  - {id: s1, phase: install, run: "PORT=$PORT npm start"}
proof:
  - {id: p1, type: exit_code_equals, expected: 0}
`
	if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "hermetic") {
		t.Fatalf("placeholder must be rejected, got %v", err)
	}
}

func TestParseStillRequiresProof(t *testing.T) {
	doc := `version: 1
project: {kind: cli, runtime: node}
execution: {max_wall_seconds: 60, max_output_bytes: 1000, install_network: none, verify_network: guest-only}
steps:
  - {id: s1, phase: launch, run: "echo hi"}
proof: []
`
	if _, err := Parse([]byte(doc)); err == nil {
		t.Fatal("hand-written contract without proof must be rejected")
	}
}

func TestAutoFromPlan(t *testing.T) {
	mkPlan := func(stack string, phases ...string) *planner.Plan {
		p := &planner.Plan{Version: "1", Stack: stack}
		for i, ph := range phases {
			p.Steps = append(p.Steps, planner.PlanStep{
				ID: fmt.Sprintf("r-%d", i), Phase: ph,
				Command: "echo x", CWD: ".", RequiresApproval: true,
			})
		}
		return p
	}
	c, err := AutoFromPlan(mkPlan("node", "install", "launch", "launch"))
	if err != nil {
		t.Fatalf("auto: %v", err)
	}
	if len(c.Steps) != 2 || c.Steps[0].ID != "auto-install" || c.Steps[1].ID != "auto-launch" {
		t.Fatalf("steps = %+v", c.Steps)
	}
	if len(c.Proof) != 0 {
		t.Fatal("auto contract must carry no oracle (PARTIAL ceiling)")
	}
	if c.Project.Runtime != "node" || c.Execution.VerifyNetwork != "guest-only" {
		t.Fatalf("contract = %+v", c)
	}
	if _, err := AutoFromPlan(mkPlan("rust", "launch")); err == nil {
		t.Fatal("unsupported stack must refuse auto contract")
	}
	if _, err := AutoFromPlan(mkPlan("node")); err == nil {
		t.Fatal("stepless plan must refuse auto contract")
	}
	if _, err := AutoFromPlan(mkPlan("unknown", "launch")); err == nil {
		t.Fatal("undetermined stack must refuse auto contract")
	}
}
