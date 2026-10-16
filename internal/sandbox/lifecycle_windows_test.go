//go:build windows

package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const n2Timeout = 60 * time.Second

func n2run(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("n2-%d-%d", os.Getpid(), time.Now().UnixNano()%1000000)
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("condition not met in %v: %s", timeout, what)
}

// TestJobLayoutRoundTrip proves the FFI struct layout empirically:
// limits written through SetInformation must read back identical.
func TestJobLayoutRoundTrip(t *testing.T) {
	job, _, err := CreateJob(JobLimits{JobMemoryMB: 512, MaxProcesses: 7})
	if err != nil {
		t.Fatalf("CreateJob failed (finding): %v", err)
	}
	defer job.Close()
	flags, active, mem, err := job.ReadLimits()
	if err != nil {
		t.Fatalf("ReadLimits failed: %v", err)
	}
	want := uint32(limitKillOnJobClose | limitDieOnUnhandled | limitActiveProcess | limitJobMemory)
	if flags != want {
		t.Fatalf("flags = 0x%X, want 0x%X: struct layout wrong", flags, want)
	}
	if active != 7 {
		t.Fatalf("active limit = %d, want 7", active)
	}
	if mem != 512<<20 {
		t.Fatalf("job memory = %d, want %d", mem, 512<<20)
	}
}

func TestCPUCapAppliedLive(t *testing.T) {
	job, applied, err := CreateJob(JobLimits{JobMemoryMB: 512, MaxProcesses: 8, CPURatePercent: 50})
	if err != nil {
		t.Fatalf("CreateJob failed: %v", err)
	}
	defer job.Close()
	if !applied {
		t.Fatal("CPU hard cap was requested but not applied")
	}
}

// TestSessionLifecycleLive covers Prepare -> LaunchInJob (sanitized
// env) -> Finalize with full removal proof.
func TestSessionLifecycleLive(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sessions := t.TempDir()

	s, err := Prepare(ctx, sessions, n2run(t), DefaultJobLimits(), nil)
	if err != nil {
		t.Fatalf("prepare failed (finding): %v", err)
	}
	env := SanitizeEnv(s.Workspace, nil, map[string]string{"LANG": "C"})
	code, out, err := LaunchInJob(ctx, s, `C:\Windows\System32\cmd.exe`,
		[]string{"/c", "set"}, env, n2Timeout)
	if err != nil || code != 0 {
		t.Fatalf("set failed: code=%d err=%v out=%.200q", code, err, out)
	}
	lines := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if k, v, ok := strings.Cut(ln, "="); ok {
			lines[strings.ToUpper(k)] = v
		}
	}
	if lines["USERPROFILE"] != s.Workspace {
		t.Fatalf("USERPROFILE not isolated: %q", lines["USERPROFILE"])
	}
	if lines["SYSTEMROOT"] != `C:\Windows` {
		t.Fatalf("SystemRoot wrong: %q", lines["SYSTEMROOT"])
	}
	if _, ok := lines["SSH_AUTH_SOCK"]; ok {
		t.Fatal("parent SSH socket leaked into sandbox env")
	}

	code, out, err = LaunchInJob(ctx, s, `C:\Windows\System32\cmd.exe`,
		[]string{"/c", "echo N2_OK"}, env, n2Timeout)
	if err != nil || code != 0 || !strings.Contains(out, "N2_OK") {
		t.Fatalf("echo failed: code=%d err=%v out=%q", code, err, out)
	}

	if err := Finalize(&s); err != nil {
		t.Fatalf("finalize failed: %v", err)
	}
	if _, serr := os.Stat(s.Workspace); !os.IsNotExist(serr) {
		t.Fatal("workspace survived finalize")
	}
	// Removal proof via re-creation.
	if _, err := CreateProfile(s.ProfileName, s.ProfileName, "x"); err != nil {
		t.Fatalf("profile removal unproven: %v", err)
	}
	_ = DeleteProfile(s.ProfileName)
}

// TestParallelSessionsIsolationLive proves that two independent controller
// runs can coexist. Cancelling/finalizing A must not remove B's profile,
// workspace, journal, or process capability. The probe is first-party cmd
// only; no repository content, network, credentials, or host paths are used.
func TestParallelSessionsIsolationLive(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sessions := t.TempDir()

	type prepared struct {
		s   Session
		err error
	}
	results := make(chan prepared, 2)
	for _, id := range []string{"parallel-a-" + n2run(t), "parallel-b-" + n2run(t)} {
		id := id
		go func() {
			s, err := Prepare(ctx, sessions, id, DefaultJobLimits(), nil)
			results <- prepared{s: s, err: err}
		}()
	}
	a := <-results
	b := <-results
	if a.err != nil || b.err != nil {
		if a.err == nil {
			_ = Finalize(&a.s)
		}
		if b.err == nil {
			_ = Finalize(&b.s)
		}
		t.Fatalf("parallel prepare failed: A=%v B=%v", a.err, b.err)
	}
	aDone, bDone := false, false
	t.Cleanup(func() {
		if !aDone {
			_ = Finalize(&a.s)
		}
		if !bDone {
			_ = Finalize(&b.s)
		}
	})
	if a.s.RunID == b.s.RunID || a.s.ProfileName == b.s.ProfileName || a.s.Workspace == b.s.Workspace {
		t.Fatalf("parallel resources were not unique: A=%+v B=%+v", a.s, b.s)
	}

	envA := SanitizeEnv(a.s.Workspace, nil, nil)
	envB := SanitizeEnv(b.s.Workspace, nil, nil)
	cmd := `C:\Windows\System32\cmd.exe`
	if code, out, err := LaunchInJob(ctx, a.s, cmd, []string{"/c", "echo A>marker.txt"}, envA, n2Timeout); err != nil || code != 0 {
		t.Fatalf("A marker failed: code=%d out=%q err=%v", code, out, err)
	}
	if code, out, err := LaunchInJob(ctx, b.s, cmd, []string{"/c", "echo B>marker.txt"}, envB, n2Timeout); err != nil || code != 0 {
		t.Fatalf("B marker failed: code=%d out=%q err=%v", code, out, err)
	}

	if err := a.s.Cancel(); err != nil {
		t.Fatalf("cancel A failed: %v", err)
	}
	// B remains usable after A's job is cancelled.
	if code, out, err := LaunchInJob(ctx, b.s, cmd, []string{"/c", "echo B_STILL_ALIVE"}, envB, n2Timeout); err != nil || code != 0 || !strings.Contains(out, "B_STILL_ALIVE") {
		t.Fatalf("B was affected by A cancellation: code=%d out=%q err=%v", code, out, err)
	}
	if _, err := os.Stat(filepath.Join(b.s.Workspace, "marker.txt")); err != nil {
		t.Fatalf("B workspace disappeared after A cancellation: %v", err)
	}

	if err := Finalize(&a.s); err != nil {
		t.Fatalf("finalize A failed: %v", err)
	}
	aDone = true
	if _, err := os.Stat(b.s.Workspace); err != nil {
		t.Fatalf("B workspace disappeared after A finalization: %v", err)
	}
	if _, err := os.Stat(filepath.Join(b.s.Workspace, "marker.txt")); err != nil {
		t.Fatalf("B marker disappeared after A finalization: %v", err)
	}

	if err := Finalize(&b.s); err != nil {
		t.Fatalf("finalize B failed: %v", err)
	}
	bDone = true
	if _, err := os.Stat(a.s.Workspace); !os.IsNotExist(err) {
		t.Fatalf("A workspace survived cleanup: %v", err)
	}
	if _, err := os.Stat(b.s.Workspace); !os.IsNotExist(err) {
		t.Fatalf("B workspace survived cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sessions, journalDirName, a.s.RunID+".json")); !os.IsNotExist(err) {
		t.Fatalf("A journal survived cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sessions, journalDirName, b.s.RunID+".json")); !os.IsNotExist(err) {
		t.Fatalf("B journal survived cleanup: %v", err)
	}
}

// TestConcurrentFinalizeIsIdempotentLive guards the lifecycle handle
// boundary: callers may race a UI cancel/cleanup path, but only one cleanup
// owns the job/profile/journal handles and both callers receive success.
func TestConcurrentFinalizeIsIdempotentLive(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	sessions := t.TempDir()
	s, err := Prepare(context.Background(), sessions, n2run(t), DefaultJobLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	a, b := s, s
	results := make(chan error, 2)
	go func() { results <- Finalize(&a) }()
	go func() { results <- Finalize(&b) }()
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent finalize returned error: %v", err)
		}
	}
	if _, err := os.Stat(s.Workspace); !os.IsNotExist(err) {
		t.Fatalf("workspace survived concurrent finalize: %v", err)
	}
}

// TestConcurrentCancelCopiesLive proves that copied Session values share the
// job state: a second Cancel must observe the first close and never reuse the
// stale native handle.
func TestConcurrentCancelCopiesLive(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	sessions := t.TempDir()
	s, err := Prepare(context.Background(), sessions, n2run(t), DefaultJobLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	a, b := s, s
	results := make(chan error, 2)
	go func() { results <- a.Cancel() }()
	go func() { results <- b.Cancel() }()
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatalf("concurrent cancel returned error: %v", err)
		}
	}
	if err := Finalize(&a); err != nil {
		t.Fatalf("finalize after concurrent cancel failed: %v", err)
	}
	if _, err := os.Stat(s.Workspace); !os.IsNotExist(err) {
		t.Fatalf("workspace survived cancel/finalize: %v", err)
	}
}

// TestRecoveryAfterWorkspaceGoneLive proves that a transient profile-delete
// failure cannot strand the profile forever after the workspace is already
// gone. Recovery accepts only the exact run-bound missing path and still
// removes the profile and journal.
func TestRecoveryAfterWorkspaceGoneLive(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	sessions := t.TempDir()
	s, err := Prepare(context.Background(), sessions, n2run(t), DefaultJobLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Cancel(); err != nil {
		t.Fatal(err)
	}
	// Crash simulation: release the process-lifetime lease without finalizing.
	releaseControllerMutex(syscall.Handle(s.ControllerMutex))
	s.ControllerMutex = 0
	if err := os.RemoveAll(s.Workspace); err != nil {
		t.Fatal(err)
	}
	cleaned, err := RecoverOrphans(sessions)
	if err != nil {
		t.Fatalf("recovery after missing workspace: %v", err)
	}
	if len(cleaned) != 1 || cleaned[0] != s.RunID {
		t.Fatalf("recovery did not clean missing-workspace run: %v", cleaned)
	}
	if _, err := os.Stat(filepath.Join(sessions, journalDirName, s.RunID+".json")); !os.IsNotExist(err) {
		t.Fatalf("journal survived recovery: %v", err)
	}
}

func TestPrepareRefusesExistingWorkspace(t *testing.T) {
	sessions := t.TempDir()
	runID := "existing-workspace"
	workspace := filepath.Join(sessions, runID)
	if err := os.Mkdir(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(context.Background(), sessions, runID, DefaultJobLimits(), nil); err == nil {
		t.Fatal("Prepare accepted a pre-existing workspace")
	}
	if _, err := os.Stat(workspace); err != nil {
		t.Fatalf("existing workspace was altered: %v", err)
	}
}

func TestRecoveryRefusesActiveControllerLease(t *testing.T) {
	sessions := t.TempDir()
	s, err := Prepare(context.Background(), sessions, "active-lease", DefaultJobLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer Finalize(&s)
	if _, err := RecoverOrphans(sessions); err == nil || !strings.Contains(err.Error(), "active run") {
		t.Fatalf("recovery must refuse active lease, got %v", err)
	}
}

// TestCancelKillsTreeLive launches two concurrent job members, cancels,
// and proves both died (output stops, launches return) without finalize.
func TestCancelKillsTreeLive(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sessions := t.TempDir()

	s, err := Prepare(ctx, sessions, n2run(t), DefaultJobLimits(), nil)
	if err != nil {
		t.Fatalf("prepare failed: %v", err)
	}
	defer func() { _ = Finalize(&s) }()
	env := SanitizeEnv(s.Workspace, nil, nil)
	cmd := `C:\Windows\System32\cmd.exe`

	type result struct {
		code int
		out  string
		err  error
	}
	sleeperDone := make(chan result, 1)
	go func() {
		// Silent member: long echo run, internals only (no network,
		// no nesting: loopback is denied and nested FOR parens break
		// cmd parsing — both learned empirically).
		code, out, err := LaunchInJob(ctx, s, cmd,
			[]string{"/c", `for /L %i in (1,1,1000000) do echo %i>>sbeat.txt`},
			env, 300*time.Second)
		sleeperDone <- result{code, out, err}
	}()
	beatFile := filepath.Join(s.Workspace, "beat.txt")
	beaterDone := make(chan result, 1)
	go func() {
		code, out, err := LaunchInJob(ctx, s, cmd,
			[]string{"/c", `for /L %i in (1,1,1000000) do echo %i>>beat.txt`},
			env, 300*time.Second)
		beaterDone <- result{code, out, err}
	}()

	// Both members must be inside the job before cancellation.
	waitFor(t, "tree inside job", 20*time.Second, func() bool {
		n, err := s.ActiveProcesses()
		return err == nil && n >= 2
	})
	waitFor(t, "heartbeat flowing", 20*time.Second, func() bool {
		raw, err := os.ReadFile(beatFile)
		return err == nil && len(raw) > 0
	})

	if err := s.Cancel(); err != nil {
		t.Fatalf("cancel failed: %v", err)
	}
	timeout := time.After(30 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case r := <-sleeperDone:
			_ = r
		case r := <-beaterDone:
			_ = r
		case <-timeout:
			t.Fatal("launches did not return after cancel: tree may survive")
		}
	}

	sizeBefore := fileSize(t, beatFile)
	time.Sleep(3 * time.Second)
	if sizeAfter := fileSize(t, beatFile); sizeAfter != sizeBefore {
		t.Fatalf("heartbeat grew after cancel (%d -> %d): tree survives", sizeBefore, sizeAfter)
	}
}

func TestCapsRejectForeignSID(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sessions := t.TempDir()
	s, err := Prepare(ctx, sessions, n2run(t), DefaultJobLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = Finalize(&s) }()
	env := SanitizeEnv(s.Workspace, nil, nil)
	// Administrators SID must never become a "capability".
	_, _, err = LaunchInJobCaps(ctx, s, `C:\Windows\System32\cmd.exe`,
		[]string{"/c", "echo hi"}, env, []string{"S-1-5-32-544"}, 60*time.Second)
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("foreign SID must be refused, got %v", err)
	}
	// Malformed SID must fail, not launch.
	_, _, err = LaunchInJobCaps(ctx, s, `C:\Windows\System32\cmd.exe`,
		[]string{"/c", "echo hi"}, env, []string{"S-1-15-3-xyz"}, 60*time.Second)
	if err == nil {
		t.Fatal("malformed capability must fail")
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Size()
}

// TestRecoverOrphansLive abandons a session (crash simulation: job
// handle closed via Cancel, journal left behind), plants foreign and
// escaping records, and requires owned-only reconciliation.
func TestRecoverOrphansLive(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sessions := t.TempDir()

	s, err := Prepare(ctx, sessions, n2run(t), DefaultJobLimits(), nil)
	if err != nil {
		t.Fatalf("prepare failed: %v", err)
	}
	code, _, err := LaunchInJob(ctx, s, `C:\Windows\System32\cmd.exe`,
		[]string{"/c", "echo hi"}, SanitizeEnv(s.Workspace, nil, nil), n2Timeout)
	if err != nil || code != 0 {
		t.Fatalf("child failed: %v", err)
	}
	// Crash: close the job (tree dies via kill-on-close) but never finalize.
	if err := s.Cancel(); err != nil {
		t.Fatal(err)
	}
	// Simulate the controller process exiting: the named lease would be
	// released by Windows on process death, so release it before recovery.
	releaseControllerMutex(syscall.Handle(s.ControllerMutex))
	s.ControllerMutex = 0

	// Foreign record: profile not run-bound -> must be skipped.
	foreignProfile := fmt.Sprintf("repoproof-foreign-%d", os.Getpid())
	if _, err := CreateProfile(foreignProfile, foreignProfile, "x"); err != nil {
		t.Fatal(err)
	}
	defer DeleteProfile(foreignProfile)
	foreignDir := filepath.Join(sessions, "foreign-keep")
	if err := os.MkdirAll(foreignDir, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(foreignDir)
	foreignRec := fmt.Sprintf(`{"run_id":"foreign-keep","profile":"someone-else","workspace":%q}`+"\n", foreignDir)
	if err := os.MkdirAll(filepath.Join(sessions, journalDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessions, journalDirName, "foreign-keep.json"), []byte(foreignRec), 0o600); err != nil {
		t.Fatal(err)
	}

	cleaned, rerr := RecoverOrphans(sessions)
	if rerr == nil {
		t.Fatal("foreign record must produce a skip error, not silence")
	}
	found := false
	for _, id := range cleaned {
		if id == s.RunID {
			found = true
		}
	}
	if !found {
		t.Fatalf("owned session not reaped: %v (err %v)", cleaned, rerr)
	}
	if _, serr := os.Stat(s.Workspace); !os.IsNotExist(serr) {
		t.Fatal("owned workspace survived recovery")
	}
	// Foreign profile untouched by recovery.
	if _, err := DeriveSid(foreignProfile); err != nil {
		t.Fatalf("foreign profile touched by recovery: %v", err)
	}
	if _, serr := os.Stat(foreignDir); serr != nil {
		t.Fatal("foreign dir touched by recovery")
	}
}
