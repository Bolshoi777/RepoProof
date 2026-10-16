// Package planner converts an inspect snapshot into a structured
// candidate execution plan (G1-05, RP-005). The plan is data for review,
// never an instruction to run: every step requires explicit user
// approval at execute time (RP-006, enforced in G2), and commands
// extracted from README text are never trusted instructions.
package planner

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/repoproof/repoproof/internal/inspector"
)

// Provisional per-step timeouts in seconds. Policy review in G2;
// kept small on purpose until the worker enforces real limits.
const (
	TimeoutInstall = 300
	TimeoutLaunch  = 120
	TimeoutVerify  = 60
	TimeoutUnknown = 120
)

// NetworkNeed describes the planner's network assumption for a step.
type NetworkNeed string

const (
	NetworkNone     NetworkNeed = "none"
	NetworkPossible NetworkNeed = "possible" // install may fetch dependencies
)

// Origin pins a step to its untrusted source text.
type Origin struct {
	SourceFile string `json:"source_file"`
	LineStart  int    `json:"line_start"`
	LineEnd    int    `json:"line_end"`
}

// PlanStep is one candidate command with everything a reviewer (and
// later the worker) needs: exact cwd, env placeholders, timeout,
// network assumption and the approval flag.
type PlanStep struct {
	ID               string      `json:"id"`
	Phase            string      `json:"phase"`
	Command          string      `json:"command"`
	Origin           Origin      `json:"origin"`
	CWD              string      `json:"cwd"`
	EnvPlaceholders  []string    `json:"env_placeholders"`
	TimeoutSeconds   int         `json:"timeout_seconds"`
	Network          NetworkNeed `json:"network"`
	RequiresApproval bool        `json:"requires_approval"`
}

// Plan is the candidate execution plan for one snapshot.
type Plan struct {
	Version        string            `json:"version"`
	Source         string            `json:"source"`
	Fingerprint    string            `json:"source_fingerprint"`
	Commit         *string           `json:"commit"`
	Stack          string            `json:"stack"`
	Support        inspector.Support `json:"support"`
	AutoApprovable bool              `json:"auto_approvable"`
	NeedsReview    bool              `json:"needs_review"`
	ReviewReasons  []string          `json:"review_reasons"`
	Steps          []PlanStep        `json:"steps"`
}

var (
	dollarVar  = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
	percentVar = regexp.MustCompile(`%([A-Za-z_][A-Za-z0-9_]+)%`)
)

func timeoutFor(phase string) int {
	switch phase {
	case "install":
		return TimeoutInstall
	case "launch":
		return TimeoutLaunch
	case "verify":
		return TimeoutVerify
	default:
		return TimeoutUnknown
	}
}

// envPlaceholders finds $VAR, ${VAR} and %VAR% tokens: values the user
// must supply at approval time. Never auto-filled, never inferred.
func envPlaceholders(cmd string) []string {
	seen := map[string]bool{}
	for _, m := range dollarVar.FindAllStringSubmatch(cmd, -1) {
		seen[m[1]] = true
	}
	for _, m := range percentVar.FindAllStringSubmatch(cmd, -1) {
		seen[m[1]] = true
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Build converts a snapshot into a candidate plan. It performs no I/O
// and executes nothing.
func Build(snap *inspector.Snapshot) *Plan {
	p := &Plan{
		Version:       "1",
		Source:        snap.Source,
		Fingerprint:   snap.Fingerprint,
		Commit:        snap.Commit,
		Stack:         string(snap.Stack),
		Support:       snap.Support,
		ReviewReasons: []string{},
		Steps:         []PlanStep{},
	}

	if snap.Support != inspector.SupportSupported {
		p.ReviewReasons = append(p.ReviewReasons,
			fmt.Sprintf("stack %q is not v1-supported (support=%s)", snap.Stack, snap.Support))
	}
	if len(snap.ReadmeSteps) == 0 {
		p.ReviewReasons = append(p.ReviewReasons, "no commands extracted from README: nothing to execute")
	}

	for _, rs := range snap.ReadmeSteps {
		network := NetworkNone
		if rs.Phase == "install" {
			network = NetworkPossible
		}
		step := PlanStep{
			ID:      rs.ID,
			Phase:   rs.Phase,
			Command: rs.Command,
			Origin: Origin{
				SourceFile: rs.SourceFile,
				LineStart:  rs.LineStart,
				LineEnd:    rs.LineEnd,
			},
			// Repo-root-relative on purpose: the worker remaps it into
			// the guest workspace, so no absolute host path leaks here.
			CWD:              ".",
			EnvPlaceholders:  envPlaceholders(rs.Command),
			TimeoutSeconds:   timeoutFor(rs.Phase),
			Network:          network,
			RequiresApproval: true,
		}
		if rs.Unclosed {
			p.ReviewReasons = append(p.ReviewReasons,
				fmt.Sprintf("step %s comes from an unclosed fence and may be truncated", rs.ID))
		}
		if len(step.EnvPlaceholders) > 0 {
			p.ReviewReasons = append(p.ReviewReasons,
				fmt.Sprintf("step %s needs user-supplied env: %v", rs.ID, step.EnvPlaceholders))
		}
		p.Steps = append(p.Steps, step)
	}

	p.NeedsReview = len(p.ReviewReasons) > 0
	p.AutoApprovable = !p.NeedsReview
	return p
}
