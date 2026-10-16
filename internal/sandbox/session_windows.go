//go:build windows

package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// Session lifecycle (N2): Prepare creates profile + workspace + job and
// journals the session; Finalize terminates the tree via job close,
// deletes the profile and removes the workspace; RecoverOrphans reaps
// only provably-owned leftovers after a crash. Owned-only, always.

// journalDirName is controller-owned metadata. It must never be placed in
// the guest workspace, which is writable by the untrusted project.
const journalDirName = ".repoproof-journal"

// sessionFile is retained for older test helpers and is never consulted by
// recovery. Journals are now keyed files under journalDirName.
const sessionFile = "session.json"

var (
	// Exclusive controller-owned files provide process-lifetime leases. Unlike
	// Win32 mutexes they are not tied to the OS thread of a Go goroutine, and
	// unlike named semaphores the handle close on controller crash releases the
	// lease automatically.
	procCreateLeaseFile    = syscall.NewLazyDLL("kernel32.dll").NewProc("CreateFileW")
	controllerLeaseMu      sync.Mutex
	activeControllerLeases = map[string]bool{}
	controllerLeaseHandles = map[syscall.Handle]string{}
)

const (
	leaseGenericRead      = 0x80000000
	leaseGenericWrite     = 0x40000000
	leaseOpenAlways       = 4
	leaseFileAttribute    = 0x00000080
	leaseOpenReparse      = 0x00200000
	leaseInvalidHandle    = ^uintptr(0)
	leaseSharingViolation = syscall.Errno(32)
	leaseLockViolation    = syscall.Errno(33)
)

// Windows profile/ACL setup can briefly stall under a busy host. Keep the
// metadata gate bounded, but give an unrelated parallel Prepare enough room
// to finish instead of turning transient contention into a false failure.
const controllerSetupWait = 2 * time.Minute

func controllerLeasePath(sessionsDir string) (string, error) {
	abs, err := filepath.Abs(sessionsDir)
	if err != nil {
		return "", err
	}
	path := filepath.Join(abs, ".repoproof-controller.lease")
	if !containedPath(abs, path) {
		return "", fmt.Errorf("controller lease path escapes sessions dir")
	}
	return path, nil
}

// sessionLeasePath returns a per-run lease file. The controller lease only
// serializes short metadata mutations; this file remains held for the
// lifetime of one session so recovery can distinguish a live run from an
// orphan without blocking unrelated runs in the same sessions directory.
func sessionLeasePath(sessionsDir, runID string) (string, error) {
	if err := validRunID(runID); err != nil {
		return "", err
	}
	root, err := filepath.Abs(sessionsDir)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, journalDirName, runID+".lease")
	if !containedPath(root, path) {
		return "", fmt.Errorf("session lease path escapes sessions dir")
	}
	return path, nil
}

func controllerLeaseKey(sessionsDir string) (string, error) {
	abs, err := filepath.Abs(sessionsDir)
	if err != nil {
		return "", err
	}
	return strings.ToLower(filepath.Clean(abs)), nil
}

func acquireControllerMutex(sessionsDir string) (syscall.Handle, error) {
	return acquireControllerMutexTimeout(sessionsDir, 0)
}

func acquireFileLease(path, key string, timeout time.Duration) (syscall.Handle, error) {
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		controllerLeaseMu.Lock()
		active := activeControllerLeases[key]
		controllerLeaseMu.Unlock()
		if !active {
			break
		}
		if timeout <= 0 || !time.Now().Before(deadline) {
			return 0, fmt.Errorf("controller lease is held by an active run")
		}
		remaining := time.Until(deadline)
		if remaining > 25*time.Millisecond {
			remaining = 25 * time.Millisecond
		}
		time.Sleep(remaining)
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	for {
		h, _, callErr := procCreateLeaseFile.Call(
			uintptr(unsafe.Pointer(p)), leaseGenericRead|leaseGenericWrite, 0, 0,
			leaseOpenAlways, leaseFileAttribute|leaseOpenReparse, 0,
		)
		if h != leaseInvalidHandle {
			if info, lerr := os.Lstat(path); lerr != nil || info.Mode()&os.ModeSymlink != 0 || pathHasReparse(info) {
				_, _, _ = procCloseHandle.Call(h)
				if lerr != nil {
					return 0, fmt.Errorf("lease lstat: %w", lerr)
				}
				return 0, fmt.Errorf("lease path is a reparse point")
			}
			controllerLeaseMu.Lock()
			activeControllerLeases[key] = true
			controllerLeaseHandles[syscall.Handle(h)] = key
			controllerLeaseMu.Unlock()
			return syscall.Handle(h), nil
		}
		if callErr != leaseSharingViolation && callErr != leaseLockViolation {
			return 0, fmt.Errorf("exclusive lease %s: %w", path, callErr)
		}
		if timeout <= 0 || !time.Now().Before(deadline) {
			return 0, fmt.Errorf("controller lease is held by an active run")
		}
		remaining := time.Until(deadline)
		if remaining > 25*time.Millisecond {
			remaining = 25 * time.Millisecond
		}
		time.Sleep(remaining)
	}
}

func acquireControllerMutexTimeout(sessionsDir string, timeout time.Duration) (syscall.Handle, error) {
	key, err := controllerLeaseKey(sessionsDir)
	if err != nil {
		return 0, err
	}
	path, err := controllerLeasePath(sessionsDir)
	if err != nil {
		return 0, err
	}
	h, err := acquireFileLease(path, key, timeout)
	if err != nil && strings.Contains(err.Error(), "lease is held") {
		return 0, fmt.Errorf("controller mutex is held by an active run")
	}
	return h, err
}

func acquireSessionLease(sessionsDir, runID string) (syscall.Handle, error) {
	key, err := controllerLeaseKey(sessionsDir)
	if err != nil {
		return 0, err
	}
	path, err := sessionLeasePath(sessionsDir, runID)
	if err != nil {
		return 0, err
	}
	return acquireFileLease(path, key+"\x00session\x00"+runID, 0)
}

func releaseControllerMutex(h syscall.Handle) {
	if h != 0 {
		// Close the exclusive handle before clearing the in-process marker so a
		// waiter cannot pass the map gate while the OS still holds the file.
		_, _, _ = procCloseHandle.Call(uintptr(h))
		controllerLeaseMu.Lock()
		if key, ok := controllerLeaseHandles[h]; ok {
			delete(activeControllerLeases, key)
			delete(controllerLeaseHandles, h)
		}
		controllerLeaseMu.Unlock()
	}
}

func journalPath(sessionsDir, runID string) (string, error) {
	if err := validRunID(runID); err != nil {
		return "", err
	}
	root, err := filepath.Abs(sessionsDir)
	if err != nil {
		return "", err
	}
	p := filepath.Join(root, journalDirName, runID+".json")
	if !containedPath(root, p) {
		return "", fmt.Errorf("journal path escapes sessions dir")
	}
	return p, nil
}

func validateJournalDir(sessionsDir string) (string, error) {
	base, err := filepath.Abs(sessionsDir)
	if err != nil {
		return "", err
	}
	if err := validatePlainDirectory(base); err != nil {
		return "", fmt.Errorf("sessions dir: %w", err)
	}
	dir := filepath.Join(base, journalDirName)
	if !containedPath(base, dir) {
		return "", fmt.Errorf("journal dir escapes sessions dir")
	}
	if err := validatePlainDirectory(dir); err != nil {
		return "", fmt.Errorf("journal dir: %w", err)
	}
	return dir, nil
}

// Prepare creates a session: workspace dir, AppContainer profile with
// workspace grant, and a limited job. Any failure rolls back what was
// created, in reverse order.
func Prepare(ctx context.Context, sessionsDir, runID string, limits JobLimits, runtimeDirs []string) (Session, error) {
	var s Session
	if err := validRunID(runID); err != nil {
		return s, fmt.Errorf("prepare: %w", err)
	}
	profile := profilePrefix + runID
	if err := ValidProfileName(profile); err != nil {
		return s, fmt.Errorf("prepare: %w", err)
	}
	base, err := filepath.Abs(sessionsDir)
	if err != nil {
		return s, fmt.Errorf("prepare: sessions dir: %w", err)
	}
	if err := validatePlainDirectory(base); err != nil {
		return s, fmt.Errorf("prepare: sessions dir is not controller-owned: %w", err)
	}
	controllerMutex, err := acquireControllerMutexTimeout(base, controllerSetupWait)
	if err != nil {
		return s, fmt.Errorf("prepare: %w", err)
	}
	mutexOpen := true
	sessionLeaseOpen := false
	var sessionLease syscall.Handle
	defer func() {
		if mutexOpen {
			releaseControllerMutex(controllerMutex)
		}
		if sessionLeaseOpen {
			releaseControllerMutex(sessionLease)
			if leasePath, lerr := sessionLeasePath(base, runID); lerr == nil {
				_ = os.Remove(leasePath)
			}
		}
	}()
	ws := filepath.Join(base, runID)
	if !containedPath(base, ws) {
		return s, fmt.Errorf("prepare: workspace escapes sessions dir")
	}
	if _, err := os.Lstat(ws); err == nil {
		return s, fmt.Errorf("prepare: workspace already exists")
	} else if !os.IsNotExist(err) {
		return s, fmt.Errorf("prepare: inspect workspace: %w", err)
	}
	journal, err := journalPath(base, runID)
	if err != nil {
		return s, fmt.Errorf("prepare: %w", err)
	}
	journalDir := filepath.Dir(journal)
	if _, err := os.Lstat(journalDir); err == nil {
		if err := validatePlainDirectory(journalDir); err != nil {
			return s, fmt.Errorf("prepare: journal dir is not controller-owned: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return s, fmt.Errorf("prepare: inspect journal dir: %w", err)
	} else if err := os.Mkdir(journalDir, 0o700); err != nil {
		return s, fmt.Errorf("prepare: journal dir: %w", err)
	}
	if _, err := os.Lstat(journal); err == nil {
		return s, fmt.Errorf("prepare: journal already exists")
	} else if !os.IsNotExist(err) {
		return s, fmt.Errorf("prepare: inspect journal: %w", err)
	}
	if err := os.Mkdir(ws, 0o755); err != nil {
		return s, fmt.Errorf("prepare: mkdir workspace: %w", err)
	}
	wsCreated := true
	defer func() {
		if wsCreated {
			if verifyOwnership(base, runID, profile, ws) == nil {
				_ = os.RemoveAll(ws)
			}
		}
	}()
	// Runtime-owned subdirs referenced by SanitizeEnv must exist:
	// tools probe TEMP/HOME at startup and may fail on missing dirs.
	for _, sub := range []string{"tmp", "AppData", filepath.Join("AppData", "Local")} {
		if err := os.MkdirAll(filepath.Join(ws, sub), 0o755); err != nil {
			return s, fmt.Errorf("prepare: mkdir %s: %w", sub, err)
		}
	}

	sid, err := CreateProfile(profile, profile, "repoproof run "+runID)
	if err != nil {
		return s, fmt.Errorf("prepare: %w", err)
	}
	profileCreated := true
	defer func() {
		if profileCreated {
			_ = DeleteProfile(profile)
		}
	}()
	if err := GrantWorkspace(ctx, ws, sid); err != nil {
		return s, fmt.Errorf("prepare: %w", err)
	}

	job, cpuApplied, err := CreateJob(limits)
	if err != nil {
		return s, fmt.Errorf("prepare: %w", err)
	}
	if limits.CPURatePercent > 0 && !cpuApplied {
		_ = job.Close()
		return s, fmt.Errorf("prepare: CPU Job Object hard cap unavailable")
	}
	jobOpen := true
	defer func() {
		if jobOpen {
			_ = job.Close()
		}
	}()

	sessionLease, err = acquireSessionLease(base, runID)
	if err != nil {
		return s, fmt.Errorf("prepare: session lease: %w", err)
	}
	sessionLeaseOpen = true
	finalized := false
	jobState := &atomic.Uintptr{}
	jobState.Store(uintptr(job))
	s = Session{RunID: runID, ProfileName: profile, ProfileSID: sid, Workspace: ws, SessionsDir: base, ControllerMutex: uintptr(sessionLease), DiskBudgetMB: limits.DiskBudgetMB, Job: uintptr(job), jobState: jobState, lifecycleMu: &sync.Mutex{}, finalized: &finalized}
	rec, _ := json.Marshal(map[string]string{
		"run_id": runID, "profile": profile, "workspace": ws,
		"cpu_cap_applied": fmt.Sprint(cpuApplied),
	})
	f, err := os.OpenFile(journal, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return s, fmt.Errorf("prepare: journal: %w", err)
	}
	if _, err := f.Write(append(rec, '\n')); err != nil {
		_ = f.Close()
		return s, fmt.Errorf("prepare: journal: %w", err)
	}
	if err := f.Close(); err != nil {
		return s, fmt.Errorf("prepare: journal: %w", err)
	}
	wsCreated, profileCreated, jobOpen = false, false, false
	// The global controller lease protected metadata creation only. Keep the
	// per-session lease in Session so recovery can skip this live run while
	// other sessions proceed concurrently.
	releaseControllerMutex(controllerMutex)
	mutexOpen = false
	sessionLeaseOpen = false
	return s, nil
}

// LaunchInJob spawns the contained child suspended, assigns the whole
// future tree to the session job, then resumes. env==nil inherits
// (discouraged); pass SanitizeEnv for isolation.
func LaunchInJob(ctx context.Context, s Session, exe string, argv []string, env []string, timeout time.Duration) (int, string, error) {
	return LaunchInJobCaps(ctx, s, exe, argv, env, nil, timeout)
}

// LaunchInJobCaps is LaunchInJob with explicit lowbox capabilities
// (S-1-15-3-* only, enforced). Capabilities widen the sandbox and must
// be operator-approved per use; the default stays deny-by-default.
func LaunchInJobCaps(ctx context.Context, s Session, exe string, argv []string, env []string, caps []string, timeout time.Duration) (int, string, error) {
	jobHandle := sessionJob(&s)
	if jobHandle == 0 {
		return 0, "", fmt.Errorf("session has no job: prepare first: %w", ErrLaunchInfra)
	}
	workDir, err := sessionWorkDir(s)
	if err != nil {
		return 0, "", fmt.Errorf("%w: workdir: %v", ErrLaunchInfra, err)
	}
	pi, outR, outW, err := spawnSuspended(s.ProfileName, exe, argv, workDir, env, caps)
	if err != nil {
		return 0, "", fmt.Errorf("%w: spawn: %v", ErrLaunchInfra, err)
	}
	defer procCloseHandle.Call(uintptr(pi.hProcess))
	defer procCloseHandle.Call(uintptr(pi.hThread))
	outW.Close()
	if err := JobHandle(jobHandle).Assign(pi.hProcess); err != nil {
		procTerminate.Call(uintptr(pi.hProcess), 1)
		return 0, "", fmt.Errorf("%w: assign: %v", ErrLaunchInfra, err)
	}
	if err := ResumeThread(pi.hThread); err != nil {
		procTerminate.Call(uintptr(pi.hProcess), 1)
		return 0, "", fmt.Errorf("%w: resume: %v", ErrLaunchInfra, err)
	}
	budgetCtx, stopBudget := context.WithCancel(ctx)
	defer stopBudget()
	budgetErr := make(chan error, 1)
	budgetDone := make(chan struct{})
	if s.DiskBudgetMB > 0 {
		go watchWorkspaceBudget(budgetCtx, s.Workspace, s.DiskBudgetMB, func() {
			_ = JobHandle(jobHandle).Terminate()
		}, budgetErr, budgetDone)
	}
	code, output, runErr := waitCollect(budgetCtx, pi.hProcess, outR, timeout, s.OutputLimitBytes, func() {
		_ = JobHandle(jobHandle).Terminate()
	})
	needJoin := runErr != nil || budgetCtx.Err() != nil
	stopBudget()
	if s.DiskBudgetMB > 0 {
		<-budgetDone
	}
	var budgetFailure error
	select {
	case budgetFailure = <-budgetErr:
		needJoin = true
	default:
	}
	if needJoin {
		if joinErr := JobHandle(jobHandle).WaitEmpty(5 * time.Second); joinErr != nil && runErr == nil && budgetFailure == nil {
			runErr = fmt.Errorf("sandbox process tree did not join: %w", joinErr)
		}
	}
	if budgetFailure != nil {
		return code, output, budgetFailure
	}
	return code, output, runErr
}

// sessionWorkDir selects the staged project directory when production
// staging has created it. The workspace fallback exists only for the
// low-level native lifecycle fixtures, which intentionally test the launcher
// without a project snapshot. A production run always installs the project
// before its first launch.
func sessionWorkDir(s Session) (string, error) {
	project := filepath.Join(s.Workspace, "project")
	if _, err := os.Lstat(project); os.IsNotExist(err) {
		return s.Workspace, nil
	} else if err != nil {
		return "", err
	}
	if !containedPath(s.Workspace, project) {
		return "", fmt.Errorf("staged project escapes workspace")
	}
	if err := validatePlainDirectory(project); err != nil {
		return "", err
	}
	return project, nil
}

// Cancel terminates the whole tree by closing the job handle
// (kill-on-close), then forgets it. Idempotent.
func (s *Session) Cancel() error {
	mu := sessionLifecycleLock(s)
	mu.Lock()
	defer mu.Unlock()
	return s.cancelLocked()
}

func (s *Session) cancelLocked() error {
	jobHandle := sessionJob(s)
	if jobHandle == 0 {
		return nil
	}
	j := JobHandle(jobHandle)
	var firstErr error
	if err := j.Terminate(); err != nil {
		firstErr = err
	}
	if err := j.WaitEmpty(5 * time.Second); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := j.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	clearSessionJob(s)
	return firstErr
}

// Finalize cancels the tree, deletes the profile, removes the
// workspace journal-first (record gone only after owned resources are
// gone... actually journal removed with workspace), and reports each
// stage. Workspace removal happens only inside the sessions dir.
func Finalize(s *Session) error {
	mu := sessionLifecycleLock(s)
	mu.Lock()
	defer mu.Unlock()
	if s.finalized != nil && *s.finalized {
		return nil
	}
	var errs []string
	cancelOK := true
	if err := s.cancelLocked(); err != nil {
		cancelOK = false
		errs = append(errs, "cancel: "+err.Error())
	}
	profileOK := false
	if err := deleteProfileRetry(s.ProfileName); err != nil {
		errs = append(errs, "profile: "+err.Error())
	} else {
		profileOK = true
	}
	workspaceOK := false
	if err := verifyRecoveryOwnership(s.SessionsDir, s.RunID, s.ProfileName, s.Workspace); err != nil {
		errs = append(errs, "workspace escapes, NOT removed: "+s.Workspace)
	} else if _, statErr := os.Lstat(s.Workspace); os.IsNotExist(statErr) {
		// A prior cleanup may have removed the workspace while profile
		// deletion was transiently busy; keep the journal recoverable.
		workspaceOK = true
	} else if statErr != nil {
		errs = append(errs, "workspace inspect: "+statErr.Error())
	} else if err := os.RemoveAll(s.Workspace); err != nil {
		errs = append(errs, "workspace: "+err.Error())
	} else {
		workspaceOK = true
	}
	// Keep the receipt until every owned resource is gone.  A failed cleanup
	// must remain recoverable after a controller restart.
	if profileOK && workspaceOK {
		// The lease file is opened with share=0, so release its handle before
		// removing the journal/lease records.
		if s.ControllerMutex != 0 {
			releaseControllerMutex(syscall.Handle(s.ControllerMutex))
			s.ControllerMutex = 0
		}
		journalDir, derr := validateJournalDir(s.SessionsDir)
		if derr != nil {
			errs = append(errs, "journal: "+derr.Error())
		} else if journal, err := journalPath(s.SessionsDir, s.RunID); err != nil {
			errs = append(errs, "journal: "+err.Error())
		} else if !containedPath(journalDir, journal) {
			errs = append(errs, "journal: path escapes journal dir")
		} else if err := os.Remove(journal); err != nil && !os.IsNotExist(err) {
			errs = append(errs, "journal: "+err.Error())
		} else if leasePath, err := sessionLeasePath(s.SessionsDir, s.RunID); err != nil {
			errs = append(errs, "lease: "+err.Error())
		} else if err := os.Remove(leasePath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, "lease: "+err.Error())
		}
	}
	if len(errs) > 0 {
		if cancelOK && s.ControllerMutex != 0 {
			releaseControllerMutex(syscall.Handle(s.ControllerMutex))
			s.ControllerMutex = 0
		}
		return fmt.Errorf("finalize incomplete: %s", strings.Join(errs, "; "))
	}
	if cancelOK && s.ControllerMutex != 0 {
		releaseControllerMutex(syscall.Handle(s.ControllerMutex))
		s.ControllerMutex = 0
	}
	if s.finalized == nil {
		finished := true
		s.finalized = &finished
	} else {
		*s.finalized = true
	}
	return nil
}

// RecoverOrphans reaps sessions left behind by a crash: for each
// session.json whose profile/workspace binding verifies as owned, it
// deletes the profile and removes the workspace, then drops the
// record. Foreign or inconsistent records are skipped with an error —
// never deleted. (Live trees are already dead: their job handles died
// with the crashed controller via kill-on-close.)
func RecoverOrphans(sessionsDir string) ([]string, error) {
	// Parallel CLI/GUI starts may briefly overlap while another controller is
	// only enumerating journals. Wait boundedly for that cleanup lease; never
	// delete a workspace while an active Prepare lease remains held.
	base, err := filepath.Abs(sessionsDir)
	if err != nil {
		return nil, err
	}
	if err := validatePlainDirectory(base); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	lease, err := acquireControllerMutexTimeout(base, 30*time.Second)
	if err != nil {
		return nil, err
	}
	defer releaseControllerMutex(lease)
	cleaned := []string{}
	var errs []string
	journalDir, dirErr := validateJournalDir(base)
	if dirErr != nil {
		if os.IsNotExist(dirErr) {
			return nil, nil
		}
		return nil, dirErr
	}
	journalEntries, readErr := os.ReadDir(journalDir)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return nil, nil
		}
		return nil, readErr
	}
	for _, e := range journalEntries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		runID := strings.TrimSuffix(e.Name(), ".json")
		if err := validRunID(runID); err != nil {
			errs = append(errs, e.Name()+": invalid journal name, skipped")
			continue
		}
		jpath := filepath.Join(journalDir, e.Name())
		jinfo, lerr := os.Lstat(jpath)
		if lerr != nil {
			continue
		}
		if !jinfo.Mode().IsRegular() || jinfo.Mode()&os.ModeSymlink != 0 || jinfo.Size() > 64<<10 {
			errs = append(errs, e.Name()+": unsafe journal file, skipped")
			continue
		}
		raw, err := os.ReadFile(jpath)
		if err != nil {
			continue // no journal: not ours to reap
		}
		var rec struct {
			RunID     string `json:"run_id"`
			Profile   string `json:"profile"`
			Workspace string `json:"workspace"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			errs = append(errs, e.Name()+": corrupt journal, skipped")
			continue
		}
		if rec.RunID != runID {
			errs = append(errs, e.Name()+": journal run id mismatch, skipped")
			continue
		}
		if err := verifyRecoveryOwnership(base, runID, rec.Profile, rec.Workspace); err != nil {
			errs = append(errs, e.Name()+": "+err.Error()+", skipped")
			continue
		}
		sessionLease, leaseErr := acquireSessionLease(base, rec.RunID)
		if leaseErr != nil {
			errs = append(errs, e.Name()+": active run, skipped")
			continue
		}
		profileOK := false
		if derr := deleteProfileRetry(rec.Profile); derr != nil {
			errs = append(errs, rec.RunID+": profile: "+derr.Error())
		} else {
			profileOK = true
		}
		workspaceOK := false
		if rerr := os.RemoveAll(rec.Workspace); rerr != nil {
			errs = append(errs, rec.RunID+": workspace: "+rerr.Error())
		} else {
			workspaceOK = true
		}
		if profileOK && workspaceOK {
			releaseControllerMutex(sessionLease)
			sessionLease = 0
			if rerr := os.Remove(jpath); rerr != nil && !os.IsNotExist(rerr) {
				errs = append(errs, rec.RunID+": journal: "+rerr.Error())
			} else if leasePath, lerr := sessionLeasePath(base, rec.RunID); lerr != nil {
				errs = append(errs, rec.RunID+": lease: "+lerr.Error())
			} else if lerr := os.Remove(leasePath); lerr != nil && !os.IsNotExist(lerr) {
				errs = append(errs, rec.RunID+": lease: "+lerr.Error())
			} else {
				cleaned = append(cleaned, rec.RunID)
			}
		}
		if sessionLease != 0 {
			releaseControllerMutex(sessionLease)
		}
	}
	if len(errs) > 0 {
		return cleaned, fmt.Errorf("orphan recovery incomplete: %s", strings.Join(errs, "; "))
	}
	return cleaned, nil
}

// deleteProfileRetry tolerates async teardown: after kill-on-close
// the profile may stay busy for a moment, so retry briefly instead of
// leaking it on the first busy error.
func deleteProfileRetry(profile string) error {
	deadline := time.Now().Add(10 * time.Second)
	var err error
	for {
		if err = DeleteProfile(profile); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ActiveProcesses proxies the job query for tests and status.
func (s *Session) ActiveProcesses() (uint32, error) {
	jobHandle := sessionJob(s)
	if jobHandle == 0 {
		return 0, fmt.Errorf("no job")
	}
	return JobHandle(jobHandle).ActiveProcesses()
}
