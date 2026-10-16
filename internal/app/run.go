// Package app is the single GUI/CLI service layer (G4): the verified
// chain as callable Go code. Both the CLI and the Wails frontend call
// this package — never their own copies of the logic. No UI code here.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/repoproof/repoproof/internal/contract"
	"github.com/repoproof/repoproof/internal/evidence"
	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/orchestrate"
	"github.com/repoproof/repoproof/internal/planner"
	"github.com/repoproof/repoproof/internal/policy"
	"github.com/repoproof/repoproof/internal/pydeps"
	"github.com/repoproof/repoproof/internal/replay"
	"github.com/repoproof/repoproof/internal/reporter"
	"github.com/repoproof/repoproof/internal/sandbox"
	"github.com/repoproof/repoproof/internal/verifier"
	"github.com/repoproof/repoproof/internal/worker"
)

// VerifyParams is everything one verification run needs.
type VerifyParams struct {
	Target       string
	ContractPath string
	ApprovePath  string
	JSONOut      string
	HTMLOut      string
	EvidenceDir  string
	RunID        string // optional; generated when empty
	// NoProvision disables automatic dependency staging (offline-only
	// run even when requirements exist).
	NoProvision bool
	// ExpectedDependencyFingerprint is internal run binding. When automatic
	// provisioning resolves registry metadata again, the selection must still
	// equal the approved fingerprint or the run aborts before launch.
	ExpectedDependencyFingerprint string
}

// VerifyOutcome is the complete run result.
type VerifyOutcome struct {
	RunID    string
	ExitCode int
	Proof    []byte
	Summary  string
	Verdict  verifier.Status
}

// ExitCodeFor maps proof verdicts to CLI exit codes (single source
// of truth, finalized in ADR-009; CLI and future callers share it).
func ExitCodeFor(v verifier.Status) int {
	switch v {
	case verifier.StatusVerified:
		return 0
	case verifier.StatusBehaviorFail, verifier.StatusLaunchFail,
		verifier.StatusInstallFail, verifier.StatusDocsFail:
		return 10
	case verifier.StatusPartial, verifier.StatusInconclusive:
		return 11
	case verifier.StatusUnsupported:
		return 12
	case verifier.StatusBlockedSecurity:
		return 13
	case verifier.StatusBlockedEnv:
		return 14
	case verifier.StatusCancelled:
		return 130
	default:
		return 20
	}
}

// SupportStatus returns the native sandbox probe as JSON for the
// GUI status bar (inspect-only mode needs no sandbox).
func SupportStatus() ([]byte, error) {
	rep := sandbox.ProbeSupport()
	att := sandbox.NativeAttestation(sandbox.DefaultResourceLimits())
	raw, err := json.Marshal(map[string]any{
		"supported": att.Attested,
		"reason": func() string {
			if !rep.Supported {
				return rep.Reason
			}
			return "native API probe passed; independent security attestation is not available"
		}(),
	})
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// CheckParams is the automatic-mode input: no contract or approval
// files. The operator confirms by passing ConfirmRun after reading
// the printed plan; without it nothing runs.
type CheckParams struct {
	Target      string
	JSONOut     string
	HTMLOut     string
	EvidenceDir string
	NoProvision bool
	ConfirmRun  bool
}

// CheckTarget implements the automatic path: inspect, print the plan
// for review, and — only with explicit confirmation — run it against
// a machine-built contract with no oracle. Verdict ceiling is PARTIAL
// by construction: setup/launch evidence without behavior proof.
// Unsupported stacks and empty plans verdict without running.
func CheckTarget(ctx context.Context, p CheckParams, progress func(string)) (VerifyOutcome, error) {
	var out VerifyOutcome
	emit := func(msg string) {
		if progress != nil {
			progress(msg)
		}
	}
	if p.Target == "" {
		return out, fmt.Errorf("target is required")
	}
	if err := recoverBeforeInput(emit); err != nil {
		out.Verdict = verifier.StatusBlockedSecurity
		out.ExitCode = ExitCodeFor(out.Verdict)
		out.Summary = "startup cleanup incomplete; inspection is paused: " + err.Error()
		return out, nil
	}
	// Materialize once: URL targets become a pinned local clone that both
	// inspection and the run below read (DEBT-020). Local paths pass
	// through; cleanup runs after the chain finishes.
	local, cleanup, err := resolveTarget(ctx, p.Target)
	if err != nil {
		return out, fmt.Errorf("target: %w", err)
	}
	defer cleanup()
	rep, err := inspector.Inspect(local)
	if err != nil {
		return out, fmt.Errorf("inspect: %w", err)
	}
	plan := planner.Build(&rep.Snapshot)
	emit(fmt.Sprintf("plan: stack %s (%s), %d step(s)", plan.Stack, plan.Support, len(plan.Steps)))
	for _, s := range plan.Steps {
		emit(fmt.Sprintf("plan step: [%s] %s", s.Phase, s.Command))
	}
	if len(plan.ReviewReasons) == 0 {
		emit("plan: clean, no review reasons")
	} else {
		for _, r := range plan.ReviewReasons {
			emit("plan review: " + r)
		}
	}
	if !p.ConfirmRun {
		out.Verdict = verifier.StatusInconclusive
		out.Summary = "automatic check refused without --confirm-run: review the plan above, then confirm"
		out.ExitCode = ExitCodeFor(out.Verdict)
		return out, nil
	}
	if plan.Support == inspector.SupportUnsupported {
		out.Verdict = verifier.StatusUnsupported
		out.Summary = fmt.Sprintf("stack %q is out of scope: nothing to run", plan.Stack)
		out.ExitCode = ExitCodeFor(out.Verdict)
		return out, nil
	}
	c, err := contract.AutoFromPlan(plan)
	if err != nil {
		out.Verdict = verifier.StatusInconclusive
		out.Summary = fmt.Sprintf("automatic check unavailable: %v", err)
		out.ExitCode = ExitCodeFor(out.Verdict)
		return out, nil
	}
	depFingerprint, err := dependencyFingerprint(ctx, local)
	if err != nil {
		out.Verdict = verifier.StatusInconclusive
		out.ExitCode = ExitCodeFor(out.Verdict)
		out.Summary = "automatic check unavailable: dependency fingerprint: " + err.Error()
		return out, nil
	}
	approval := &policy.Approval{
		Version: "1", PlanFingerprint: plan.Fingerprint, Commit: plan.Commit,
		ContractFingerprint:   contract.FingerprintContract(c),
		DependencyFingerprint: depFingerprint,
		ExpiresAt:             policy.NewExpiry(time.Now().UTC()),
		Statement:             "operator confirmed automatic run at invocation",
		AcknowledgedReasons:   append([]string{}, plan.ReviewReasons...),
		ApprovedNetwork:       "guest-only",
	}
	outcome, err := finishChain(ctx, rep, plan, c, approval, attestationFor(c), chainIO{
		EvidenceDir: p.EvidenceDir, JSONOut: p.JSONOut, HTMLOut: p.HTMLOut,
		Target: local, NoProvision: p.NoProvision,
		ContractFingerprint:   contract.FingerprintContract(c),
		DependencyFingerprint: depFingerprint,
	}, emit)
	if err != nil {
		return out, err
	}
	outcome.Summary = "automatic mode: no oracle, verdict capped at PARTIAL\n" + outcome.Summary
	return outcome, nil
}

// ReplayReport checks whether a proof report may be reused in the
// current environment. It reads the report (validating it first),
// captures the current fingerprint from a fresh native attestation,
// and refuses silent reuse on any difference. Returns a human summary,
// an exit code, and a hard error only for unreadable/invalid reports.
func ReplayReport(reportPath string) (string, int, error) {
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		return "", 20, fmt.Errorf("replay: read: %w", err)
	}
	if err := reporter.ValidateProofReport(raw); err != nil {
		return "", 20, fmt.Errorf("replay: invalid proof report: %w", err)
	}
	var doc struct {
		RunID       string `json:"run_id"`
		Status      string `json:"status"`
		Environment struct {
			WorkerKind   string `json:"worker_kind"`
			ImageDigest  string `json:"image_digest"`
			Attested     bool   `json:"attested"`
			NetworkMode  string `json:"network_mode"`
			PolicyDigest string `json:"policy_digest"`
			AppVersion   string `json:"app_version"`
			Limits       *struct {
				CPUCores       int   `json:"cpu_cores"`
				MemoryMB       int   `json:"memory_mb"`
				DiskMB         int   `json:"disk_mb"`
				WallSeconds    int   `json:"wall_seconds"`
				MaxOutputBytes int64 `json:"max_output_bytes"`
			} `json:"limits"`
		} `json:"environment"`
		Snapshot struct {
			Commit string `json:"commit"`
		} `json:"snapshot"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", 20, fmt.Errorf("replay: parse: %w", err)
	}
	if doc.Status != string(verifier.StatusVerified) {
		return fmt.Sprintf("report: %s\nrecorded verdict: %s\nreplay: STALE — only VERIFIED reports can be reused\n", reportPath, doc.Status), 11, nil
	}
	if !doc.Environment.Attested {
		return fmt.Sprintf("report: %s\nrecorded verdict: %s\nreplay: STALE — report has no attested worker\n", reportPath, doc.Status), 11, nil
	}
	recorded := replay.Fingerprint{
		WorkerKind:   doc.Environment.WorkerKind,
		ImageDigest:  doc.Environment.ImageDigest,
		PolicyDigest: doc.Environment.PolicyDigest,
		Network:      doc.Environment.NetworkMode,
		AppVersion:   doc.Environment.AppVersion,
		// Proof reports don't store OS/arch/build/runtimes: those
		// fields compare equal by construction, so replay judges the
		// environment the report DOES record. Tamper evidence for
		// verdicts lives in evidence receipts (G3-05).
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}
	// Rebuild the attestation from RECORDED limits: replay must compare
	// against the policy that actually ran, not current defaults.
	// Reports without recorded limits cannot prove identical policy.
	limits := sandbox.DefaultResourceLimits()
	if doc.Environment.Limits != nil {
		l := doc.Environment.Limits
		limits = worker.ResourceLimits{
			CPUCores: l.CPUCores, MemoryMB: l.MemoryMB, DiskMB: l.DiskMB,
			WallSeconds: l.WallSeconds, MaxOutputBytes: l.MaxOutputBytes,
		}
	}
	current := replay.Capture(sandbox.NativeAttestation(limits), "", nil)
	diffs := replay.Compare(recorded, current)
	summary := fmt.Sprintf("report: %s\nrecorded verdict: %s\ncommit: %s\n",
		reportPath, doc.Status, doc.Snapshot.Commit)
	if len(diffs) == 0 {
		summary += "replay: REUSABLE in the current environment\n"
		return summary, 0, nil
	}
	summary += "replay: STALE — do not reuse:\n"
	for _, w := range diffs {
		summary += "  - " + w + "\n"
	}
	return summary, 11, nil
}

// Inspect returns the validated inspect JSON for a path.
func Inspect(target string) ([]byte, error) {
	local, cleanup, err := resolveTarget(context.Background(), target)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	rep, err := inspector.Inspect(local)
	if err != nil {
		return nil, err
	}
	return reporter.MarshalAndValidate(rep)
}

// BuildPlan returns the candidate plan JSON for a path.
func BuildPlan(target string) ([]byte, error) {
	local, cleanup, err := resolveTarget(context.Background(), target)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	rep, err := inspector.Inspect(local)
	if err != nil {
		return nil, err
	}
	p := planner.Build(&rep.Snapshot)
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// InspectAndPlan returns the validated inspection report and candidate plan
// from one pinned materialization. Keeping both reads on the same checkout
// avoids cloning a GitHub URL twice in the desktop UI.
func InspectAndPlan(target string) ([]byte, error) {
	return InspectAndPlanContext(context.Background(), target)
}

// InspectAndPlanContext is the cancellable form used by the desktop UI.
// Cancellation stops an in-flight Git operation and still runs checkout
// cleanup through the normal deferred path.
func InspectAndPlanContext(ctx context.Context, target string) ([]byte, error) {
	local, cleanup, err := resolveTarget(ctx, target)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	rep, err := inspector.Inspect(local)
	if err != nil {
		return nil, err
	}
	inspectRaw, err := reporter.MarshalAndValidate(rep)
	if err != nil {
		return nil, err
	}
	p := planner.Build(&rep.Snapshot)
	planRaw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(map[string]json.RawMessage{
		"inspect": inspectRaw,
		"plan":    planRaw,
	})
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// DraftApproval inspects, plans and writes the approval record.
// It reads and writes one file; nothing executes.
func DraftApproval(target, contractPath, statement string, ackAll bool, outPath string) (string, error) {
	if target == "" || contractPath == "" || outPath == "" || statement == "" {
		return "", fmt.Errorf("target, contract, statement and output are required")
	}
	local, cleanup, err := resolveTarget(context.Background(), target)
	if err != nil {
		return "", err
	}
	defer cleanup()
	rep, err := inspector.Inspect(local)
	if err != nil {
		return "", err
	}
	p := planner.Build(&rep.Snapshot)
	craw, err := os.ReadFile(contractPath)
	if err != nil {
		return "", err
	}
	if _, err := contract.Parse(craw); err != nil {
		return "", err
	}
	depFingerprint, err := dependencyFingerprint(context.Background(), local)
	if err != nil {
		return "", err
	}
	acked := []string{}
	if ackAll {
		acked = append(acked, p.ReviewReasons...)
	}
	ap := policy.Approval{
		Version: "1", PlanFingerprint: p.Fingerprint, Commit: p.Commit,
		ContractFingerprint:   contract.Fingerprint(craw),
		DependencyFingerprint: depFingerprint,
		ExpiresAt:             policy.NewExpiry(time.Now().UTC()),
		Statement:             statement, AcknowledgedReasons: acked,
		ApprovedNetwork: "guest-only",
	}
	raw, err := json.MarshalIndent(ap, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(outPath, append(raw, '\n'), 0o644); err != nil {
		return "", err
	}
	summary := fmt.Sprintf("approval drafted: %s\nplan fingerprint: %s\n", outPath, p.Fingerprint)
	if len(p.ReviewReasons) == 0 {
		summary += "review reasons: none (clean plan)\n"
	} else {
		summary += fmt.Sprintf("review reasons (%d):\n", len(p.ReviewReasons))
		for _, r := range p.ReviewReasons {
			mark := "PENDING"
			if ackAll {
				mark = "ACKNOWLEDGED"
			}
			summary += fmt.Sprintf("  [%s] %s\n", mark, r)
		}
		if !ackAll {
			summary += "verify will deny until every reason is acknowledged\n"
		}
	}
	return summary, nil
}

// RunVerify runs the full chain: probe recovery, inspect, plan,
// contract, approval, attestation, execution, proof report. Progress
// markers stream through progress (nil = silent). Nothing runs on host.
func RunVerify(ctx context.Context, p VerifyParams, progress func(string)) (VerifyOutcome, error) {
	var out VerifyOutcome
	emit := func(msg string) {
		if progress != nil {
			progress(msg)
		}
	}
	if p.Target == "" || p.ContractPath == "" || p.ApprovePath == "" {
		return out, fmt.Errorf("target, contract and approval file are required")
	}
	if err := recoverBeforeInput(emit); err != nil {
		out.Verdict = verifier.StatusBlockedSecurity
		out.ExitCode = ExitCodeFor(out.Verdict)
		out.Summary = "startup cleanup incomplete; verification is paused: " + err.Error()
		return out, nil
	}

	// Same single materialization as CheckTarget (DEBT-020): the run
	// reads the same pinned tree that was inspected.
	local, cleanup, err := resolveTarget(ctx, p.Target)
	if err != nil {
		return out, fmt.Errorf("target: %w", err)
	}
	defer cleanup()
	rep, err := inspector.Inspect(local)
	if err != nil {
		return out, fmt.Errorf("inspect: %w", err)
	}
	plan := planner.Build(&rep.Snapshot)

	craw, err := os.ReadFile(p.ContractPath)
	if err != nil {
		return out, fmt.Errorf("contract: %w", err)
	}
	c, err := contract.Parse(craw)
	if err != nil {
		return out, fmt.Errorf("contract: %w", err)
	}
	araw, err := os.ReadFile(p.ApprovePath)
	if err != nil {
		return out, fmt.Errorf("approval: %w", err)
	}
	var approval policy.Approval
	if err := json.Unmarshal(araw, &approval); err != nil {
		return out, fmt.Errorf("approval: bad JSON: %w", err)
	}
	depFingerprint, err := dependencyFingerprint(ctx, local)
	if err != nil {
		return out, fmt.Errorf("dependencies: %w", err)
	}

	return finishChain(ctx, rep, plan, c, &approval, attestationFor(c), chainIO{
		EvidenceDir: p.EvidenceDir, JSONOut: p.JSONOut, HTMLOut: p.HTMLOut,
		RunID: p.RunID, Target: local, NoProvision: p.NoProvision,
		ContractFingerprint:   contract.Fingerprint(craw),
		DependencyFingerprint: depFingerprint,
	}, emit)
}

// attestationFor binds contract-declared budgets to the native backend.
func attestationFor(c *contract.Contract) worker.Attestation {
	limits := sandbox.DefaultResourceLimits()
	limits.WallSeconds = c.Execution.MaxWallSeconds
	limits.MaxOutputBytes = c.Execution.MaxOutputBytes
	return sandbox.NativeAttestation(limits)
}

// recoverBeforeInput enforces the native lifecycle contract at the trust
// boundary: orphan cleanup happens before URL materialization or local-tree
// inspection. Non-Windows remains inspect-only and has no native journals.
func recoverBeforeInput(emit func(string)) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	sessionsDir := filepath.Join(os.TempDir(), "repoproof-sessions")
	cleaned, err := sandbox.RecoverOrphans(sessionsDir)
	if err != nil {
		return err
	}
	if len(cleaned) > 0 {
		emit(fmt.Sprintf("startup recovery: reaped %d orphaned session(s)", len(cleaned)))
	}
	return nil
}

// dependencyFingerprint covers the dependency declarations that can alter
// a staged run. It is intentionally computed from the materialized tree, so
// changing requirements or lockfiles after approval invalidates the record.
func dependencyFingerprint(ctx context.Context, target string) (string, error) {
	names := []string{"requirements.txt", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
	var material []byte
	found := false
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(target, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", err
		}
		found = true
		material = append(material, name...)
		material = append(material, 0)
		material = append(material, raw...)
		material = append(material, 0)
		if name == "requirements.txt" {
			pins, perr := pydeps.ParseRequirements(raw)
			if perr != nil {
				return "", perr
			}
			resolved, rerr := pydeps.ResolvedFingerprint(ctx, "", pins)
			if rerr != nil {
				return "", rerr
			}
			material = append(material, []byte("python-resolved\x00")...)
			material = append(material, resolved...)
			material = append(material, 0)
		}
	}
	if !found {
		return "", nil
	}
	// Runtime identity is part of the provision contract even when the
	// current project has no Python install step; changing the pinned
	// runtime must force a fresh approval.
	material = append(material, []byte("python-runtime\x00")...)
	material = append(material, sandbox.PinnedPython().SHA256...)
	sum := sha256.Sum256(material)
	return hex.EncodeToString(sum[:]), nil
}

func dependencyFingerprintForRequirements(target string, reqRaw []byte, resolved string) (string, error) {
	names := []string{"requirements.txt", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
	var material []byte
	found := false
	for _, name := range names {
		var raw []byte
		var err error
		if name == "requirements.txt" {
			raw = reqRaw
			if len(raw) == 0 {
				continue
			}
		} else {
			raw, err = os.ReadFile(filepath.Join(target, name))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return "", err
			}
		}
		found = true
		material = append(material, name...)
		material = append(material, 0)
		material = append(material, raw...)
		material = append(material, 0)
		if name == "requirements.txt" && resolved != "" {
			material = append(material, []byte("python-resolved\x00")...)
			material = append(material, resolved...)
			material = append(material, 0)
		}
	}
	if !found {
		return "", nil
	}
	material = append(material, []byte("python-runtime\x00")...)
	material = append(material, sandbox.PinnedPython().SHA256...)
	sum := sha256.Sum256(material)
	return hex.EncodeToString(sum[:]), nil
}

// chainIO carries the per-run file outputs and flags into runChain.
type chainIO struct {
	EvidenceDir           string
	JSONOut               string
	HTMLOut               string
	RunID                 string
	Target                string
	NoProvision           bool
	ContractFingerprint   string
	DependencyFingerprint string
}

// finishChain runs execution, seals evidence and builds the proof
// report. Shared by verify (human contract) and check (auto contract)
// so both paths enforce identical gates.
func finishChain(ctx context.Context, rep *inspector.Report, plan *planner.Plan, c *contract.Contract, approval *policy.Approval, att worker.Attestation, io chainIO, emit func(string)) (VerifyOutcome, error) {
	var out VerifyOutcome
	p := VerifyParams{Target: io.Target, EvidenceDir: io.EvidenceDir, NoProvision: io.NoProvision, RunID: io.RunID, JSONOut: io.JSONOut, HTMLOut: io.HTMLOut, ExpectedDependencyFingerprint: io.DependencyFingerprint}

	sessionsDir := filepath.Join(os.TempDir(), "repoproof-sessions")
	if cleaned, err := sandbox.RecoverOrphans(sessionsDir); err != nil {
		emit(fmt.Sprintf("orphan recovery: %v", err))
	} else if len(cleaned) > 0 {
		emit(fmt.Sprintf("reaped %d orphaned session(s)", len(cleaned)))
	}

	storeDir := p.EvidenceDir
	var autoStore bool
	if storeDir == "" {
		var merr error
		storeDir, merr = os.MkdirTemp("", "repoproof-evidence-")
		if merr != nil {
			return out, fmt.Errorf("evidence: %w", merr)
		}
		autoStore = true
		defer os.RemoveAll(storeDir)
	}
	store, err := evidence.Open(storeDir)
	if err != nil {
		return out, fmt.Errorf("evidence: %w", err)
	}

	runID := p.RunID
	if runID == "" {
		runID = fmt.Sprintf("run-%d-%d", time.Now().UnixNano(), os.Getpid())
	}
	orchProgress := func(msg string) { emit(msg) }
	var bundle *depsBundle
	if att.Attested {
		bundle, err = autoDepsSnapshot(ctx, p, plan, &rep.Snapshot)
		if err != nil {
			return out, err
		}
	} else {
		// The worker gate is checked by orchestrate.Execute. Do not download
		// runtimes or resolve package indexes while execute is unavailable.
		emit("execute: blocked before dependency provisioning (worker attestation unavailable)")
	}
	var onSession func(sandbox.Session) ([]string, error)
	var prologue func(sandbox.Session) []orchestrate.StepRequest
	var depsNote string
	runtimeFP := ""
	if bundle != nil {
		defer bundle.Cleanup()
		onSession, prologue, depsNote = bundle.OnSession, bundle.Prologue, bundle.Note
		runtimeFP = bundle.RuntimeFingerprint
	}
	// Every executable step runs from a fresh controller-owned project copy.
	// The inspected source tree is never exposed as a guest working directory.
	projectStage := func(s sandbox.Session) ([]string, error) {
		if err := inspector.StageSnapshot(rep.Snapshot, rep.Source, s.Workspace); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if onSession == nil {
		onSession = projectStage
	} else {
		depsStage := onSession
		onSession = func(s sandbox.Session) ([]string, error) {
			if _, err := projectStage(s); err != nil {
				return nil, err
			}
			return depsStage(s)
		}
	}
	res := orchestrate.Execute(ctx, orchestrate.Config{
		RunID: runID, SessionsDir: sessionsDir,
		Plan: plan, Contract: c, Approval: approval, Attestation: att,
		ContractFingerprint:   io.ContractFingerprint,
		DependencyFingerprint: io.DependencyFingerprint,
		Limits:                sandbox.DefaultJobLimits(), Store: store,
		Progress: orchProgress, OnSession: onSession, Prologue: prologue,
		Prepare: func(ctx context.Context, sessionsDir, runID string) (sandbox.Session, error) {
			return sandbox.Prepare(ctx, sessionsDir, runID, sandbox.DefaultJobLimits(), nil)
		},
		Launch: func(ctx context.Context, s sandbox.Session, exe string, argv []string, env []string, timeout time.Duration) (int, string, error) {
			if runtimeFP != "" {
				got, ferr := fingerprintTree(filepath.Join(s.Workspace, "rt"))
				if ferr != nil || got != runtimeFP {
					if ferr == nil {
						ferr = fmt.Errorf("runtime tree changed")
					}
					return 0, "", fmt.Errorf("%w: runtime integrity: %v", sandbox.ErrLaunchInfra, ferr)
				}
			}
			return sandbox.LaunchInJob(ctx, s, exe, argv, env, timeout)
		},
		Finalize: func(s *sandbox.Session) error { return sandbox.Finalize(s) },
	})

	inputs := reporter.ProofInput{
		RunID: res.RunID, Verdict: res.Verdict, Setup: res.Setup,
		Launch: res.Launch, Oracle: res.Oracle,
		Limitations: append(res.Reasons,
			"cpu: 50% Job Object hard cap requested; exact scheduler behavior is Windows/SKU dependent",
			"disk budget: 4GB sampled workspace monitor; this is not a filesystem quota"),
	}
	if depsNote != "" {
		inputs.Limitations = append(inputs.Limitations, depsNote)
	}
	for _, s := range res.Steps {
		inputs.Steps = append(inputs.Steps, reporter.ProofStep{
			ID: s.ID, Phase: s.Phase, Command: s.Command, ExitCode: s.ExitCode,
			Output: s.Output, Error: s.Error, EvidenceRef: s.EvidenceRef,
		})
	}
	for _, a := range c.Assertions() {
		inputs.Assertions = append(inputs.Assertions, a)
	}
	proof, err := reporter.BuildProofReport(&rep.Snapshot, att, inputs)
	if err != nil {
		return out, fmt.Errorf("report: %w", err)
	}
	if p.JSONOut != "" {
		if werr := os.WriteFile(p.JSONOut, proof, 0o644); werr != nil {
			return out, fmt.Errorf("write %s: %w", p.JSONOut, werr)
		}
	}
	if p.HTMLOut != "" {
		f, herr := os.Create(p.HTMLOut)
		if herr != nil {
			return out, fmt.Errorf("create %s: %w", p.HTMLOut, herr)
		}
		herr = reporter.WriteProofHTML(proof, f)
		cerr := f.Close()
		if herr != nil || cerr != nil {
			return out, fmt.Errorf("write %s failed", p.HTMLOut)
		}
	}
	summary := fmt.Sprintf("run: %s\nverdict: %s\nsetup: %s launch: %s oracle: %s\n",
		res.RunID, res.Verdict, res.Setup, res.Launch, res.Oracle)
	for _, r := range res.Reasons {
		summary += fmt.Sprintf("  note: %s\n", r)
	}
	out = VerifyOutcome{
		RunID: res.RunID, ExitCode: ExitCodeFor(res.Verdict),
		Proof: proof, Summary: summary, Verdict: res.Verdict,
	}
	_ = autoStore
	return out, nil
}
