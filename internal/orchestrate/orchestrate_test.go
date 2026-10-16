package orchestrate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
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

func testAttestation() worker.Attestation {
	return worker.Attestation{
		WorkerKind: "test-backend", ImageDigest: "sha256:" + strings.Repeat("a", 64), PolicyDigest: "sha256:" + strings.Repeat("b", 64),
		Network: worker.NetworkGuestOnly, Attested: true, Limits: worker.DefaultLimits(),
	}
}

func testPlan() *planner.Plan {
	return &planner.Plan{
		Version: "1", Source: "x", Fingerprint: strings.Repeat("a", 64),
		Stack: "node", AutoApprovable: true,
		Steps: []planner.PlanStep{
			{ID: "readme-1", Phase: "install", Command: "echo setup-ok", CWD: ".", RequiresApproval: true},
			{ID: "readme-2", Phase: "launch", Command: "echo HELLO", CWD: ".", RequiresApproval: true},
		},
	}
}

func testContract() *contract.Contract {
	c, err := contract.Parse([]byte(`version: 1
project: {kind: cli, runtime: node}
execution: {max_wall_seconds: 60, max_output_bytes: 1000, install_network: none, verify_network: guest-only}
steps:
  - {id: install, phase: install, from_readme: true}
  - {id: launch, phase: launch, from_readme: true}
proof:
  - {id: exit0, type: exit_code_equals, expected: 0}
  - {id: says-hello, type: stdout_contains, expected: "HELLO"}
`))
	if err != nil {
		panic(err)
	}
	return c
}

func testApproval(p *planner.Plan) *policy.Approval {
	return &policy.Approval{
		Version: "1", PlanFingerprint: p.Fingerprint, Statement: "test approval",
		ApprovedNetwork: string(worker.NetworkGuestOnly),
		ExpiresAt:       policy.NewExpiry(time.Now().UTC()),
	}
}

// fakeEnv wires fakes: outputs maps command substrings to results.
func fakeEnv(outputs map[string]struct {
	code int
	out  string
	err  error
}, store *evidence.Store) Config {
	plan := testPlan()
	return Config{
		RunID: "run-w1", Plan: plan, Contract: testContract(),
		Approval: testApproval(plan), Attestation: testAttestation(),
		Limits: sandbox.DefaultJobLimits(), Store: store,
		Prepare: func(ctx context.Context, _, _ string) (sandbox.Session, error) {
			return sandbox.Session{RunID: "run-w1"}, nil
		},
		Launch: func(_ context.Context, _ sandbox.Session, _ string, argv []string, _ []string, _ time.Duration) (int, string, error) {
			joined := strings.Join(argv, " ")
			for sub, r := range outputs {
				if strings.Contains(joined, sub) {
					return r.code, r.out, r.err
				}
			}
			return 127, "no fake for " + joined, nil
		},
		Finalize: func(_ *sandbox.Session) error { return nil },
	}
}

func TestHappyChainVerifies(t *testing.T) {
	store, err := evidence.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "setup-ok\n", nil},
		"echo HELLO":    {0, "HELLO\n", nil},
	}, store)
	res := Execute(context.Background(), cfg)
	if res.Verdict != verifier.StatusVerified {
		t.Fatalf("verdict = %q reasons=%v steps=%+v", res.Verdict, res.Reasons, res.Steps)
	}
	if !res.EvidenceOK || res.Receipt == "" {
		t.Fatalf("evidence not sealed: %+v", res)
	}
	if err := store.Verify(cfg.RunID); err != nil {
		t.Fatalf("evidence verify: %v", err)
	}
	if len(res.Steps) != 2 || res.Steps[0].Command != "echo setup-ok" {
		t.Fatalf("from_readme resolution wrong: %+v", res.Steps)
	}
}

func TestNoOracleChainIsPartial(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "setup-ok\n", nil},
		"echo HELLO":    {0, "HELLO\n", nil},
	}, store)
	cfg.Contract.Proof = nil
	res := Execute(context.Background(), cfg)
	if res.Verdict != verifier.StatusPartial {
		t.Fatalf("successful setup/launch without oracle = %q, want PARTIAL", res.Verdict)
	}
}

func TestOutputTruncationRemainsPartial(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "setup-ok\n", nil},
		"echo HELLO":    {0, strings.Repeat("x", 128<<10), nil},
	}, store)
	cfg.Contract.Proof = nil
	res := Execute(context.Background(), cfg)
	if res.Verdict != verifier.StatusPartial || len(res.Steps) != 2 || len(res.Steps[1].Output) != 1000 {
		t.Fatalf("bounded output changed verdict or size: verdict=%q steps=%d output=%d", res.Verdict, len(res.Steps), len(res.Steps[1].Output))
	}
}

func TestCleanupFailureBlocksVerdict(t *testing.T) {
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "setup-ok\n", nil},
		"echo HELLO":    {0, "HELLO\n", nil},
	}, nil)
	cfg.Finalize = func(_ *sandbox.Session) error { return errors.New("profile still exists") }
	res := Execute(context.Background(), cfg)
	if res.Verdict != verifier.StatusBlockedSecurity || !strings.Contains(strings.Join(res.Reasons, "\n"), "cleanup failed") {
		t.Fatalf("cleanup failure was not fail-closed: %+v", res)
	}
}

func TestBrokenChainFails(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "setup-ok\n", nil},
		"echo HELLO":    {0, "WRONG\n", nil},
	}, store)
	if res := Execute(context.Background(), cfg); res.Verdict != verifier.StatusBehaviorFail {
		t.Fatalf("verdict = %q", res.Verdict)
	}
}

func TestLaunchFailChain(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "setup-ok\n", nil},
		"echo HELLO":    {3, "crash\n", nil},
	}, store)
	if res := Execute(context.Background(), cfg); res.Verdict != verifier.StatusLaunchFail {
		t.Fatalf("verdict = %q", res.Verdict)
	}
}

// TestLaunchInfraIsInconclusive replays DEBT-019 deterministically: the
// launcher reports the child never started (sentinel), so the run must
// verdict INCONCLUSIVE, never a behavioral LAUNCH_FAIL.
func TestLaunchInfraIsInconclusive(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "setup-ok\n", nil},
		"echo HELLO":    {0, "", fmt.Errorf("%w: spawn: CreateProcessW failed", sandbox.ErrLaunchInfra)},
	}, store)
	res := Execute(context.Background(), cfg)
	if res.Verdict != verifier.StatusInconclusive {
		t.Fatalf("verdict = %q, want INCONCLUSIVE; reasons=%v", res.Verdict, res.Reasons)
	}
	if len(res.Steps) != 2 || !res.Steps[1].Infra {
		t.Fatalf("launch step must be recorded with infra flag: %+v", res.Steps)
	}
	found := false
	for _, r := range res.Reasons {
		if strings.Contains(r, "launcher infra") && strings.Contains(r, res.Steps[1].ID) {
			found = true
		}
	}
	if !found {
		t.Fatalf("infra reason missing: %v", res.Reasons)
	}
}

func TestWorkspaceBudgetBlocksSecurity(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "setup-ok\n", nil},
		"echo HELLO":    {0, "", fmt.Errorf("%w: 4194305 bytes", sandbox.ErrWorkspaceBudget)},
	}, store)
	res := Execute(context.Background(), cfg)
	if res.Verdict != verifier.StatusInconclusive {
		t.Fatalf("workspace budget must be inconclusive: %q reasons=%v", res.Verdict, res.Reasons)
	}
	if len(res.Steps) != 2 || !res.Steps[1].ResourceLimit {
		t.Fatalf("resource limit step must be recorded: %+v", res.Steps)
	}
}

// TestInstallInfraIsInconclusive covers the install phase: a never-started
// dependency step must not become INSTALL_FAIL.
func TestInstallInfraIsInconclusive(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "", fmt.Errorf("%w: assign failed", sandbox.ErrLaunchInfra)},
		"echo HELLO":    {0, "HELLO\n", nil},
	}, store)
	if res := Execute(context.Background(), cfg); res.Verdict != verifier.StatusInconclusive {
		t.Fatalf("verdict = %q, want INCONCLUSIVE", res.Verdict)
	}
}

// TestTimeoutStaysBehavioral locks the boundary: a started-but-hung run
// (plain timeout error, no sentinel) keeps the old LAUNCH_FAIL mapping.
func TestTimeoutStaysBehavioral(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "setup-ok\n", nil},
		"echo HELLO":    {1, "partial\n", errors.New("sandboxed process timed out")},
	}, store)
	res := Execute(context.Background(), cfg)
	if res.Verdict != verifier.StatusLaunchFail {
		t.Fatalf("verdict = %q, want LAUNCH_FAIL", res.Verdict)
	}
	if !res.Steps[1].TimedOut || res.Steps[1].Infra {
		t.Fatalf("timeout step flags wrong: %+v", res.Steps[1])
	}
}

func TestInstallFailChain(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {1, "missing dep\n", nil},
		"echo HELLO":    {0, "HELLO\n", nil},
	}, store)
	if res := Execute(context.Background(), cfg); res.Verdict != verifier.StatusInstallFail {
		t.Fatalf("verdict = %q", res.Verdict)
	}
}

func TestInstallTimeoutFailsSetup(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo dependency": {1, "partial\n", errors.New("sandboxed process timed out")},
		"echo HELLO":      {0, "HELLO\n", nil},
	}, store)
	cfg.Prologue = func(sandbox.Session) []StepRequest {
		return []StepRequest{{ID: "deps-install", Phase: "install", Command: "echo dependency", Timeout: time.Second}}
	}
	res := Execute(context.Background(), cfg)
	if res.Verdict != verifier.StatusInstallFail || len(res.Steps) == 0 || !res.Steps[0].TimedOut {
		t.Fatalf("install timeout = verdict %q steps=%+v, want INSTALL_FAIL and timed_out", res.Verdict, res.Steps)
	}
}

func TestRunWallLimitIsEnforcedAcrossChain(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "setup-ok\n", nil},
	}, store)
	cfg.Contract.Execution.MaxWallSeconds = 1
	cfg.Launch = func(ctx context.Context, _ sandbox.Session, _ string, argv []string, _ []string, _ time.Duration) (int, string, error) {
		if strings.Contains(strings.Join(argv, " "), "HELLO") {
			<-ctx.Done()
			return 0, "", ctx.Err()
		}
		return 0, "setup-ok\n", nil
	}
	res := Execute(context.Background(), cfg)
	if res.Verdict != verifier.StatusInconclusive {
		t.Fatalf("wall timeout verdict = %q, want INCONCLUSIVE; reasons=%v", res.Verdict, res.Reasons)
	}
	if !strings.Contains(strings.Join(res.Reasons, "\n"), "run wall limit exceeded") {
		t.Fatalf("wall timeout reason missing: %v", res.Reasons)
	}
}

func TestUnresolvableFromReadmeIsDocsFail(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{}, store)
	cfg.Plan.Steps = nil // no plan commands: from_readme unresolvable
	cfg.Approval = testApproval(cfg.Plan)
	if res := Execute(context.Background(), cfg); res.Verdict != verifier.StatusDocsFail {
		t.Fatalf("verdict = %q reasons=%v", res.Verdict, res.Reasons)
	}
}

func TestNoApprovalIsInconclusive(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{}, store)
	cfg.Approval = nil
	res := Execute(context.Background(), cfg)
	if res.Verdict != verifier.StatusInconclusive {
		t.Fatalf("verdict = %q", res.Verdict)
	}
	if len(res.Steps) != 0 {
		t.Fatal("denied run must execute nothing")
	}
}

func TestUnattestedWorkerIsBlocked(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{}, store)
	cfg.Attestation = worker.Attestation{}
	if res := Execute(context.Background(), cfg); res.Verdict != verifier.StatusBlockedSecurity {
		t.Fatalf("verdict = %q", res.Verdict)
	}
}

func TestUnsupportedPlanStaysUnsupported(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "setup-ok\n", nil},
		"echo HELLO":    {0, "HELLO\n", nil},
	}, store)
	cfg.Plan.Support = inspector.SupportUnsupported
	if res := Execute(context.Background(), cfg); res.Verdict != verifier.StatusUnsupported {
		t.Fatalf("verdict = %q, support must beat passing steps", res.Verdict)
	}
}

func TestRuntimeMismatchNoted(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	newCfg := func(stack string) Config {
		cfg := fakeEnv(map[string]struct {
			code int
			out  string
			err  error
		}{
			"echo setup-ok": {0, "setup-ok\n", nil},
			"echo HELLO":    {0, "HELLO\n", nil},
		}, store)
		cfg.Plan.Stack = stack
		return cfg
	}
	res := Execute(context.Background(), newCfg("node"))
	for _, r := range res.Reasons {
		if strings.Contains(r, "differs from detected plan stack") {
			t.Fatalf("matching runtime must stay silent: %v", res.Reasons)
		}
	}
	res = Execute(context.Background(), newCfg("python"))
	found := false
	for _, r := range res.Reasons {
		if strings.Contains(r, `contract runtime "node" differs from detected plan stack "python"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("mismatch must be noted: %v", res.Reasons)
	}
	if res.Verdict != verifier.StatusVerified {
		t.Fatalf("mismatch notes, never blocks: %q", res.Verdict)
	}
}

func TestPrepareFailureIsInternal(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{}, store)
	cfg.Prepare = func(context.Context, string, string) (sandbox.Session, error) {
		return sandbox.Session{}, fmt.Errorf("no backend: %w", errors.New("boom"))
	}
	if res := Execute(context.Background(), cfg); res.Verdict != verifier.StatusErrorInternal {
		t.Fatalf("verdict = %q", res.Verdict)
	}
}

func TestProgressSequence(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "setup-ok\n", nil},
		"echo HELLO":    {0, "HELLO\n", nil},
	}, store)
	var events []string
	cfg.Progress = func(msg string) { events = append(events, msg) }
	if res := Execute(context.Background(), cfg); res.Verdict != verifier.StatusVerified {
		t.Fatalf("verdict = %q", res.Verdict)
	}
	want := []string{"authorized", "session ready", "step install started", "step launch started", "verdict VERIFIED"}
	joined := strings.Join(events, "\n")
	idx := -1
	for _, w := range want {
		at := strings.Index(joined, w)
		if at < 0 || at < idx {
			t.Fatalf("progress out of order or missing %q in %v", w, events)
		}
		idx = at
	}
}

func TestCancelledBeforeStart(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{}, store)
	ran := false
	cfg.Prepare = func(context.Context, string, string) (sandbox.Session, error) {
		ran = true
		return sandbox.Session{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := Execute(ctx, cfg)
	if res.Verdict != verifier.StatusCancelled {
		t.Fatalf("verdict = %q", res.Verdict)
	}
	if ran || len(res.Steps) != 0 {
		t.Fatal("cancelled run must create nothing and run nothing")
	}
}

func TestCancelledMidRun(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{}, store)
	ctx, cancel := context.WithCancel(context.Background())
	cfg.Launch = func(ctx context.Context, _ sandbox.Session, _ string, _ []string, _ []string, _ time.Duration) (int, string, error) {
		cancel() // abort during the first step
		<-ctx.Done()
		return 0, "partial\n", ctx.Err()
	}
	res := Execute(ctx, cfg)
	if res.Verdict != verifier.StatusCancelled {
		t.Fatalf("verdict = %q, partial data must never become a verdict", res.Verdict)
	}
}

func TestPrologueRunsFirstAndCanFailSetup(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	var order []string
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{
		"echo setup-ok": {0, "setup-ok\n", nil},
		"echo HELLO":    {0, "HELLO\n", nil},
	}, store)
	origLaunch := cfg.Launch
	cfg.Launch = func(ctx context.Context, s sandbox.Session, exe string, argv []string, env []string, timeout time.Duration) (int, string, error) {
		order = append(order, exe+" "+strings.Join(argv, " "))
		if strings.Contains(exe, "pip") {
			return 1, "pip boom\n", nil
		}
		return origLaunch(ctx, s, exe, argv, env, timeout)
	}
	cfg.Prologue = func(sandbox.Session) []StepRequest {
		return []StepRequest{{ID: "deps-install", Exe: "pip", Args: []string{"install", "x"}, Timeout: time.Minute}}
	}
	res := Execute(context.Background(), cfg)
	if res.Verdict != verifier.StatusInstallFail {
		t.Fatalf("verdict = %q, want INSTALL_FAIL", res.Verdict)
	}
	if len(order) == 0 || !strings.Contains(order[0], "pip") {
		t.Fatalf("prologue must run first: %v", order)
	}
	if res.Steps[0].ID != "deps-install" || res.Steps[0].Phase != "install" {
		t.Fatalf("prologue step not recorded as install: %+v", res.Steps[0])
	}
	if res.Steps[0].EvidenceRef == "" {
		t.Fatal("prologue step lacks evidence ref")
	}
}

func TestOnSessionErrorAbortsInconclusive(t *testing.T) {
	store, _ := evidence.Open(t.TempDir())
	cfg := fakeEnv(map[string]struct {
		code int
		out  string
		err  error
	}{}, store)
	cfg.OnSession = func(sandbox.Session) ([]string, error) {
		return nil, fmt.Errorf("staging failed")
	}
	res := Execute(context.Background(), cfg)
	if res.Verdict != verifier.StatusInconclusive {
		t.Fatalf("verdict = %q", res.Verdict)
	}
	if len(res.Steps) != 0 {
		t.Fatal("failed staging must run nothing")
	}
}
