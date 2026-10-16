// Package orchestrate runs the verified chain end to end (W1):
// authorize -> resolve -> setup -> launch -> oracle -> verdict ->
// sealed evidence. Side effects (session, launch, finalize) enter
// through small function fields, so unit tests prove the chain with
// fakes while one live test proves it inside the AppContainer.
// Nothing here shells out on its own.
package orchestrate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/repoproof/repoproof/internal/contract"
	"github.com/repoproof/repoproof/internal/evidence"
	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/planner"
	"github.com/repoproof/repoproof/internal/policy"
	"github.com/repoproof/repoproof/internal/sandbox"
	"github.com/repoproof/repoproof/internal/verifier"
	"github.com/repoproof/repoproof/internal/worker"
)

// SessionFactory creates an isolated session. Production passes a
// sandbox.Prepare wrapper; tests inject fakes.
type SessionFactory func(ctx context.Context, sessionsDir, runID string) (sandbox.Session, error)

// Launcher runs one approved step inside the session.
type Launcher func(ctx context.Context, s sandbox.Session, exe string, argv []string, env []string, timeout time.Duration) (int, string, error)

// Finalizer tears a session down.
type Finalizer func(s *sandbox.Session) error

// StepRequest is one executable unit: either a shell command
// (Command, Exe empty) or a direct binary invocation (Exe + Args).
type StepRequest struct {
	ID      string
	Phase   string
	Command string
	Exe     string
	Args    []string
	Timeout time.Duration
}

// Config binds everything one run needs.
type Config struct {
	RunID                 string
	SessionsDir           string
	Plan                  *planner.Plan
	Contract              *contract.Contract
	Approval              *policy.Approval
	ContractFingerprint   string
	DependencyFingerprint string
	Attestation           worker.Attestation
	Limits                sandbox.JobLimits
	Store                 *evidence.Store

	Prepare  SessionFactory
	Launch   Launcher
	Finalize Finalizer
	// Progress receives human-readable stage markers in order
	// (nil = silent). Used by CLI/GUI for live timelines.
	Progress func(string)
	// OnSession stages files into the fresh workspace right after
	// Prepare (runtimes, wheels, manifests) and returns extra PATH dirs
	// for sandboxed steps (e.g. the staged runtime). Errors abort internal.
	OnSession func(sandbox.Session) ([]string, error)
	// Prologue builds install-phase steps after staging (dependency
	// installs). They run first, recorded and evidence-covered.
	Prologue func(sandbox.Session) []StepRequest
}

// StepResult is the recorded outcome of one executed step.
type StepResult struct {
	ID          string `json:"id"`
	Phase       string `json:"phase"`
	Command     string `json:"command"`
	ExitCode    int    `json:"exit_code"`
	Output      string `json:"output,omitempty"`
	TimedOut    bool   `json:"timed_out"`
	Error       string `json:"error,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
	// Infra marks steps whose child never started (sandbox.ErrLaunchInfra):
	// no project behavior was observed, so the run verdict must be
	// INCONCLUSIVE rather than a behavioral FAIL.
	Infra bool `json:"infra,omitempty"`
	// ResourceLimit marks a sandbox-enforced resource stop. It is a
	// security/infrastructure condition, never a project behavior failure.
	ResourceLimit bool `json:"resource_limit,omitempty"`
}

// Result is the complete run outcome with its evidence receipt.
type Result struct {
	RunID      string          `json:"run_id"`
	Verdict    verifier.Status `json:"verdict"`
	Setup      verifier.Phase  `json:"setup"`
	Launch     verifier.Phase  `json:"launch"`
	Oracle     verifier.Oracle `json:"oracle"`
	Steps      []StepResult    `json:"steps"`
	Reasons    []string        `json:"reasons,omitempty"`
	Receipt    string          `json:"receipt,omitempty"`
	EvidenceOK bool            `json:"evidence_ok"`
}

// Execute runs the chain. It never falls back to host execution: every
// step runs through cfg.Launch inside the prepared session, and any
// refusal short-circuits to an honest non-VERIFIED verdict.
func Execute(ctx context.Context, cfg Config) Result {
	res := Result{RunID: cfg.RunID, Steps: []StepResult{}}
	// The contract wall budget covers the complete chain, including setup and
	// dependency staging. Per-step launcher timeouts are not sufficient: a
	// plan with many individually valid steps could otherwise run forever.
	wallSeconds := 0
	if cfg.Contract != nil {
		wallSeconds = cfg.Contract.Execution.MaxWallSeconds
	}
	if wallSeconds <= 0 {
		wallSeconds = worker.DefaultLimits().WallSeconds
	}
	if wallSeconds <= 0 {
		res.Reasons = append(res.Reasons, "execution refused: no positive wall-time limit")
		res.Verdict = verifier.StatusErrorInternal
		return res
	}
	runCtx, cancelRun := context.WithTimeout(ctx, time.Duration(wallSeconds)*time.Second)
	defer cancelRun()
	ctx = runCtx
	emit := func(msg string) {
		if cfg.Progress != nil {
			cfg.Progress(msg)
		}
	}
	finalize := func() error { return nil }
	finish := func() Result {
		if finalizeErr := finalize(); finalizeErr != nil {
			res.Reasons = append(res.Reasons, "sandbox cleanup failed: "+finalizeErr.Error())
			res.Verdict = verifier.StatusBlockedSecurity
			res.EvidenceOK = false
		}
		if cfg.Store != nil {
			if receipt, err := cfg.Store.Seal(cfg.RunID); err == nil {
				res.Receipt = receipt
				res.EvidenceOK = cfg.Store.Verify(cfg.RunID) == nil
			}
		}
		return res
	}
	// finalize is replaced once a session exists. Keeping it in finish()
	// guarantees every return path tears down the worker before evidence is
	// sealed, while early policy denials remain side-effect free.

	// Operator abort before anything starts: no session, no steps,
	// CANCELLED verdict. Partial data must never become a verdict.
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			res.Reasons = append(res.Reasons, fmt.Sprintf("run wall limit exceeded (%ds) before start", wallSeconds))
			res.Verdict = verifier.StatusInconclusive
		} else {
			res.Reasons = append(res.Reasons, "cancelled before start")
			res.Verdict = verifier.StatusCancelled
		}
		return finish()
	}

	var contractFingerprint []string
	if cfg.ContractFingerprint != "" {
		contractFingerprint = []string{cfg.ContractFingerprint}
		if cfg.DependencyFingerprint != "" {
			contractFingerprint = append(contractFingerprint, cfg.DependencyFingerprint)
		}
	}
	if err := policy.Authorize(cfg.Attestation, cfg.Plan, cfg.Approval, contractFingerprint...); err != nil {
		res.Reasons = []string{err.Error()}
		// Worker-side denials are security blocks; pure approval
		// problems mean no approved run exists: inconclusive, never verified.
		if strings.Contains(err.Error(), "worker gate") {
			res.Verdict = verifier.StatusBlockedSecurity
		} else {
			res.Verdict = verifier.StatusInconclusive
		}
		return finish()
	}
	emit("authorized")

	resolved, docsMismatch, setupGap, launchGap, resolveErr := resolveSteps(cfg.Contract, cfg.Plan)
	if resolveErr != nil {
		res.Reasons = append(res.Reasons, resolveErr.Error())
	}
	// The contract runtime claim is not verified by detection: any
	// mismatch (including undetected stacks) is noted, never silenced.
	// Polyglot runs stay allowed; reviewers must read the note.
	if cfg.Contract.Project.Runtime != cfg.Plan.Stack {
		res.Reasons = append(res.Reasons, fmt.Sprintf(
			"contract runtime %q differs from detected plan stack %q",
			cfg.Contract.Project.Runtime, cfg.Plan.Stack))
	}
	s, err := cfg.Prepare(ctx, cfg.SessionsDir, cfg.RunID)
	if err != nil {
		res.Reasons = append(res.Reasons, fmt.Sprintf("prepare: %v", err))
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			res.Reasons = append(res.Reasons, fmt.Sprintf("run wall limit exceeded (%ds) during prepare", wallSeconds))
			res.Verdict = verifier.StatusInconclusive
		} else if errors.Is(ctx.Err(), context.Canceled) {
			res.Verdict = verifier.StatusCancelled
		} else {
			res.Verdict = verifier.StatusErrorInternal
		}
		return finish()
	}
	if cfg.Contract != nil && cfg.Contract.Execution.MaxOutputBytes > 0 {
		s.OutputLimitBytes = cfg.Contract.Execution.MaxOutputBytes
	}
	finalized := false
	finalize = func() error {
		if finalized || cfg.Finalize == nil {
			return nil
		}
		finalized = true
		return cfg.Finalize(&s)
	}
	emit("session ready")

	env := sandbox.SanitizeEnv(s.Workspace, nil, nil)
	if cfg.OnSession != nil {
		envExtra, err := cfg.OnSession(s)
		if err != nil {
			res.Reasons = append(res.Reasons, fmt.Sprintf("staging: %v", err))
			// No project step started. A source/runtime staging refusal is
			// an unproven run, never an internal success or behavior result.
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				res.Reasons = append(res.Reasons, fmt.Sprintf("run wall limit exceeded (%ds) during staging", wallSeconds))
				res.Verdict = verifier.StatusInconclusive
			} else if errors.Is(ctx.Err(), context.Canceled) {
				res.Verdict = verifier.StatusCancelled
			} else {
				res.Verdict = verifier.StatusInconclusive
			}
			return finish()
		}
		if len(envExtra) > 0 {
			env = sandbox.SanitizeEnv(s.Workspace, envExtra, nil)
		}
	}
	var lastObs verifier.Observation
	setupOK, launchOK := !setupGap, !launchGap
	infraFailed := false
	infraReason := ""
	resourceFailed := false
	resourceReason := ""
	stopForResource := false
	markInfra := func(sr StepResult) {
		if sr.Infra && !infraFailed {
			infraFailed = true
			infraReason = fmt.Sprintf("launcher infra on step %s: %s; no behavior observed", sr.ID, sr.Error)
		}
		if sr.ResourceLimit && !resourceFailed {
			resourceFailed = true
			resourceReason = fmt.Sprintf("sandbox resource limit on step %s: %s", sr.ID, sr.Error)
			stopForResource = true
		}
	}
	// Prologue (dependency installs) runs first as install-phase steps:
	// recorded, evidence-covered, and able to fail the setup verdict.
	if cfg.Prologue != nil {
		for _, ps := range cfg.Prologue(s) {
			st := resolvedStep{ID: ps.ID, Phase: "install", Command: ps.Command, Exe: ps.Exe, Args: ps.Args, Timeout: ps.Timeout}
			emit(fmt.Sprintf("step %s started", st.ID))
			start := time.Now()
			sr := runStep(ctx, cfg, s, env, st)
			res.Steps = append(res.Steps, sr)
			res.Steps[len(res.Steps)-1].EvidenceRef = putEvidence(cfg, &res, st, sr)
			emit(fmt.Sprintf("step %s done in %s", st.ID, time.Since(start).Round(time.Millisecond)))
			markInfra(sr)
			if stopForResource {
				break
			}
			if sr.ExitCode != 0 || sr.Error != "" {
				setupOK = false
			}
			if ctx.Err() != nil {
				break
			}
		}
	}
	for _, st := range resolved {
		if stopForResource {
			break
		}
		emit(fmt.Sprintf("step %s started", st.ID))
		start := time.Now()
		sr := runStep(ctx, cfg, s, env, st)
		res.Steps = append(res.Steps, sr)
		res.Steps[len(res.Steps)-1].EvidenceRef = putEvidence(cfg, &res, st, sr)
		emit(fmt.Sprintf("step %s done in %s", st.ID, time.Since(start).Round(time.Millisecond)))
		markInfra(sr)
		if ctx.Err() != nil {
			break
		}
		if st.Phase == "install" && (sr.ExitCode != 0 || sr.Error != "") {
			setupOK = false
		}
		if st.Phase == "launch" {
			lastObs = verifier.Observation{ExitCode: sr.ExitCode, Stdout: sr.Output}
			if sr.ExitCode != 0 || sr.Error != "" {
				launchOK = false
			}
		}
	}

	// Operator abort mid-run overrides any partial outcome: partial
	// data must never become a verdict.
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			res.Reasons = append(res.Reasons, fmt.Sprintf("run wall limit exceeded (%ds)", wallSeconds))
			res.Verdict = verifier.StatusInconclusive
			emit("wall limit exceeded")
		} else {
			res.Reasons = append(res.Reasons, "cancelled during run")
			res.Verdict = verifier.StatusCancelled
			emit("cancelled")
		}
		return finish()
	}

	res.Setup = verifier.PhasePass
	if !setupOK {
		res.Setup = verifier.PhaseFail
	}
	res.Launch = verifier.PhasePass
	if !launchOK {
		res.Launch = verifier.PhaseFail
	}
	oracle := verifier.OracleAbsent
	if len(cfg.Contract.Proof) > 0 && anyLaunchRan(resolved) {
		ok, failed := verifier.Evaluate(cfg.Contract.Assertions(), lastObs)
		if !ok {
			res.Reasons = append(res.Reasons, fmt.Sprintf("assertions failed: %s", strings.Join(failed, ",")))
		}
		oracle = verifier.OracleFromOutcome(ok)
	}
	res.Oracle = oracle
	// Capability, not risk: an out-of-scope stack stays UNSUPPORTED
	// even with an explicit approval (approval covers risks in scope,
	// it cannot conjure a runtime). Priority handled inside Decide.
	res.Verdict = verifier.Decide(verifier.Inputs{
		Setup: res.Setup, Launch: res.Launch, Oracle: res.Oracle,
		DocsMismatch: docsMismatch,
		Unsupported:  cfg.Plan.Support == inspector.SupportUnsupported,
	})
	// Launcher infra (child never started) observed no project behavior:
	// fail closed to INCONCLUSIVE, never a behavioral verdict. The step
	// records keep Error+Infra, and the reason flows into the report
	// limitations. Cancellation above keeps priority: this branch only
	// runs when the context is live.
	if infraFailed {
		res.Reasons = append(res.Reasons, infraReason)
		res.Verdict = verifier.StatusInconclusive
	}
	if resourceFailed {
		res.Reasons = append(res.Reasons, resourceReason)
		// A resource stop invalidates the run as evidence of behavior, but
		// does not prove that the repository itself failed. Stop further
		// steps and report an infrastructure-uncertain outcome.
		res.Verdict = verifier.StatusInconclusive
		res.EvidenceOK = false
	}
	emit(fmt.Sprintf("verdict %s", res.Verdict))
	return finish()
}

type resolvedStep struct {
	ID      string
	Phase   string
	Command string
	Exe     string
	Args    []string
	Timeout time.Duration
}

// resolveSteps binds contract steps to commands: inline Run directly,
// from_readme via the approved plan (same phase, declaration order).
// Unresolvable from_readme marks docsMismatch plus a per-phase gap, so
// vacuous passes are impossible: a phase with no runnable command
// fails, and DocsMismatch steers the verdict to DOCS_FAIL.
func resolveSteps(c *contract.Contract, p *planner.Plan) ([]resolvedStep, bool, bool, bool, error) {
	byPhase := map[string][]planner.PlanStep{}
	for _, s := range p.Steps {
		byPhase[s.Phase] = append(byPhase[s.Phase], s)
	}
	used := map[string]int{}
	out := []resolvedStep{}
	docsMismatch := false
	setupGap, launchGap := false, false
	var firstErr error
	for _, s := range c.Steps {
		timeout := time.Duration(s.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = phaseTimeout(s.Phase)
		}
		if !s.FromReadme {
			out = append(out, resolvedStep{ID: s.ID, Phase: s.Phase, Command: s.Run, Timeout: timeout})
			continue
		}
		pool := byPhase[s.Phase]
		if used[s.Phase] >= len(pool) {
			docsMismatch = true
			if s.Phase == "install" {
				setupGap = true
			} else {
				launchGap = true
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("step %q: no plan command for phase %q", s.ID, s.Phase)
			}
			continue
		}
		ps := pool[used[s.Phase]]
		used[s.Phase]++
		out = append(out, resolvedStep{ID: s.ID, Phase: s.Phase, Command: ps.Command, Timeout: timeout})
	}
	return out, docsMismatch, setupGap, launchGap, firstErr
}

func phaseTimeout(phase string) time.Duration {
	switch phase {
	case "install":
		return planner.TimeoutInstall * time.Second
	case "launch":
		return planner.TimeoutLaunch * time.Second
	default:
		return planner.TimeoutUnknown * time.Second
	}
}

func anyLaunchRan(steps []resolvedStep) bool {
	for _, s := range steps {
		if s.Phase == "launch" {
			return true
		}
	}
	return false
}

// runStep executes one resolved command through the sandbox launcher.
// v1 runs the command via the Windows session shell (full system path,
// no PATH lookup games); the command text itself comes only from the
// validated contract or the approved plan.
func runStep(ctx context.Context, cfg Config, s sandbox.Session, env []string, st resolvedStep) StepResult {
	sr := StepResult{ID: st.ID, Phase: st.Phase, Command: st.Command}
	exe, argv := `C:\Windows\System32\cmd.exe`, []string{"/c", st.Command}
	if st.Exe != "" {
		exe, argv = st.Exe, st.Args
		sr.Command = exe + " " + strings.Join(argv, " ")
	}
	code, output, err := cfg.Launch(ctx, s, exe, argv, env, st.Timeout)
	sr.ExitCode = code
	outputLimit := int64(64 << 10)
	if cfg.Contract != nil && cfg.Contract.Execution.MaxOutputBytes > 0 {
		outputLimit = cfg.Contract.Execution.MaxOutputBytes
	}
	if int64(len(output)) > outputLimit {
		output = output[:int(outputLimit)]
	}
	sr.Output = output
	if err != nil {
		if strings.Contains(err.Error(), "timed out") {
			sr.TimedOut = true
		}
		sr.Error = err.Error()
		// Only sentinel-marked never-started failures count as infra.
		// Any other error (timeouts, unknown launcher faults) keeps the
		// old fail-the-phase mapping: default-deny, never silent.
		sr.Infra = errors.Is(err, sandbox.ErrLaunchInfra)
		sr.ResourceLimit = errors.Is(err, sandbox.ErrWorkspaceBudget) || errors.Is(err, sandbox.ErrWorkspaceScan)
	}
	return sr
}

func putEvidence(cfg Config, res *Result, st resolvedStep, sr StepResult) string {
	if cfg.Store == nil {
		return ""
	}
	payload := fmt.Sprintf("exit=%d\nerror=%s\n---\n%s", sr.ExitCode, sr.Error, sr.Output)
	rec, err := cfg.Store.Put(cfg.RunID, st.ID, "output", []byte(payload), false)
	if err != nil {
		res.Reasons = append(res.Reasons, fmt.Sprintf("evidence put failed for %s: %v", st.ID, err))
		return ""
	}
	return rec.Ref
}
