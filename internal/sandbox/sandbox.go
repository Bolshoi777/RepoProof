// Package sandbox implements the native Windows AppContainer backend
// (RP-NATIVE-SANDBOX-001): per-run AppContainer profile + workspace,
// launch of approved steps inside, denial outside, full cleanup.
// No Docker, no WSL, no admin on the ordinary path.
//
// Layering: this file holds the portable contract (SandboxBackend,
// SupportReport, Session) and pure helpers. Win32 calls live in
// appcontainer_windows.go (stdlib syscall only — no new dependencies);
// other platforms get an UNSUPPORTED stub.
package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"github.com/repoproof/repoproof/internal/worker"
)

// validatePlainDirectory proves that a controller-owned directory and all
// existing parents are ordinary directories.  Cleanup must never follow a
// junction/reparse point supplied through a journal or a replaced path.
func validatePlainDirectory(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	cur := filepath.Clean(abs)
	for {
		info, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return fmt.Errorf("%q is not a directory", cur)
		}
		if info.Mode()&os.ModeSymlink != 0 || pathHasReparse(info) {
			return fmt.Errorf("%q is a symlink or reparse point", cur)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return nil
}

// ErrUnsupported marks any sandbox operation on a platform without
// the native backend.
var ErrUnsupported = errors.New("native sandbox unsupported on this platform")

// ErrLaunchInfra marks launcher failures where the child process never
// started (spawn/assign/resume refused, no job). A step carrying this
// error observed no project behavior: callers must verdict
// INCONCLUSIVE, never a behavioral FAIL. Started-but-failed runs
// (nonzero exits, timeouts) are NOT wrapped: they are honest
// observations of the project's behavior.
var ErrLaunchInfra = errors.New("launcher infra: process never started")

// ErrWorkspaceBudget marks the best-effort disk-growth monitor. It is a
// security/resource failure, never a claim that a filesystem quota existed.
var ErrWorkspaceBudget = errors.New("workspace disk budget exceeded")

// ErrWorkspaceScan marks an unsafe or incomplete workspace accounting scan.
// A run cannot produce behavioral proof when its resource boundary cannot be
// measured fail-closed.
var ErrWorkspaceScan = errors.New("workspace disk budget scan failed")

// SupportReport is the PROBE_NATIVE_SECURITY_SUPPORT outcome.
type SupportReport struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
}

// Session binds every run-owned resource to one run ID for journaled
// cleanup. The profile is deleted and the workspace removed on
// Finalize; nothing else may be touched. Job is the in-memory job
// handle on Windows (0 elsewhere); it is never serialized.
type Session struct {
	RunID           string
	ProfileName     string
	ProfileSID      string `json:"-"`
	Workspace       string
	ControllerMutex uintptr `json:"-"`
	// SessionsDir is trusted controller storage. It is deliberately
	// separate from Workspace: the guest receives access only to the
	// latter, never to lifecycle metadata used for orphan cleanup.
	SessionsDir  string `json:"-"`
	DiskBudgetMB uint64 `json:"-"`
	// OutputLimitBytes is copied from the reviewed contract by the
	// orchestrator. Zero keeps the low-level fixture default.
	OutputLimitBytes int64   `json:"-"`
	Job              uintptr `json:"-"`
	// jobState is shared by Session copies so a Cancel on one copy makes the
	// underlying handle unavailable to all other copies.
	jobState *atomic.Uintptr `json:"-"`
	// lifecycleMu is shared by Session copies passed through callbacks, so
	// concurrent Cancel/Finalize cannot double-close handles or cleanup paths.
	lifecycleMu *sync.Mutex `json:"-"`
	finalized   *bool       `json:"-"`
}

var fallbackSessionLifecycleMu sync.Mutex

func sessionLifecycleLock(s *Session) *sync.Mutex {
	if s.lifecycleMu != nil {
		return s.lifecycleMu
	}
	return &fallbackSessionLifecycleMu
}

func sessionJob(s *Session) uintptr {
	if s.jobState != nil {
		return s.jobState.Load()
	}
	return s.Job
}

func clearSessionJob(s *Session) {
	if s.jobState != nil {
		s.jobState.Store(0)
	}
	s.Job = 0
}

// StepEvidence is the recorded outcome of one sandboxed step.
type StepEvidence struct {
	RunID    string `json:"run_id"`
	StepID   string `json:"step_id"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
	TimedOut bool   `json:"timed_out"`
}

// SandboxBackend is the execution boundary (amendment §B). N1
// implements ProbeSupport plus the profile/launch helpers; full
// Prepare/Execute/Cancel/Finalize/RecoverOrphans lands in N2.
type SandboxBackend interface {
	ProbeSupport() SupportReport
	Prepare(runID, plan string) (Session, error)
	Execute(session Session, stepID, command string, timeoutMs uint32) (StepEvidence, error)
	Cancel(session Session) error
	Finalize(session Session) error
	RecoverOrphans() ([]string, error)
}

// maxProfileNameLen bounds AppContainer profile names.
const maxProfileNameLen = 64

// ValidProfileName enforces AppContainer naming so generated names can
// never smuggle path separators or wildcards into Win32 calls.
func ValidProfileName(name string) error {
	if name == "" || len(name) > maxProfileNameLen {
		return fmt.Errorf("profile name length out of range: %q", name)
	}
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' {
			continue
		}
		return fmt.Errorf("profile name has forbidden character %q in %q", c, name)
	}
	return nil
}

// IcaclsGrantArgs builds the exact icacls invocation granting a profile
// SID full control over its workspace with inheritance. Fixed shape:
// only the workspace path and the derived SID vary, both RepoProof-owned.
func IcaclsGrantArgs(workspace, sid string) ([]string, error) {
	if workspace == "" || sid == "" {
		return nil, errors.New("workspace and sid must not be empty")
	}
	if !strings.HasPrefix(sid, "S-1-") {
		return nil, fmt.Errorf("not an SID string: %q", sid)
	}
	return []string{"icacls", workspace, "/grant", "*" + sid + ":(OI)(CI)F"}, nil
}

// profilePrefix binds profile names to RepoProof runs.
const profilePrefix = "repoproof-"

// SanitizeEnv builds the child environment from scratch (DEBT-016):
// the parent block is NEVER inherited. Base carries only what a
// Windows child needs plus run-owned temp dirs; PATH is minimal
// (System32 + caller runtime dirs); caller extras are explicit and win
// on collision. Result is sorted for determinism.
func SanitizeEnv(workspace string, runtimeDirs []string, extra map[string]string) []string {
	tmp := filepath.Join(workspace, "tmp")
	pathDirs := append([]string{`C:\Windows\System32`}, runtimeDirs...)
	env := map[string]string{
		"SystemRoot":   `C:\Windows`,
		"SystemDrive":  "C:",
		"TEMP":         tmp,
		"TMP":          tmp,
		"HOME":         workspace,
		"USERPROFILE":  workspace,
		"APPDATA":      filepath.Join(workspace, "AppData"),
		"LOCALAPPDATA": filepath.Join(workspace, "AppData", "Local"),
		"PATH":         strings.Join(pathDirs, ";"),
	}
	for k, v := range extra {
		env[strings.ToUpper(k)] = v
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// verifyOwnership enforces the owned-only rule: profile name must be
// the run-bound RepoProof name, workspace must resolve inside the
// sessions dir and match the run folder.
func verifyOwnership(sessionsDir, runID, profile, workspace string) error {
	if err := validRunID(runID); err != nil {
		return err
	}
	if profile != profilePrefix+runID {
		return fmt.Errorf("profile %q is not run-bound", profile)
	}
	if err := ValidProfileName(profile); err != nil {
		return err
	}
	baseAbs, err := filepath.Abs(sessionsDir)
	if err != nil {
		return err
	}
	if err := validatePlainDirectory(baseAbs); err != nil {
		return fmt.Errorf("sessions dir is not controller-owned: %w", err)
	}
	workspaceAbs, err := filepath.Abs(workspace)
	if err != nil {
		return err
	}
	if !containedPath(baseAbs, workspaceAbs) {
		return fmt.Errorf("workspace is outside sessions dir")
	}
	runPath := filepath.Join(baseAbs, runID)
	if !containedPath(baseAbs, runPath) {
		return fmt.Errorf("run path escapes sessions dir")
	}
	if err := validatePlainDirectory(runPath); err != nil {
		return fmt.Errorf("run workspace is not controller-owned: %w", err)
	}
	if err := validatePlainDirectory(workspaceAbs); err != nil {
		return fmt.Errorf("workspace is not controller-owned: %w", err)
	}
	want, err := filepath.EvalSymlinks(runPath)
	if err != nil {
		return fmt.Errorf("owned workspace unavailable: %w", err)
	}
	got, err := filepath.EvalSymlinks(workspaceAbs)
	if err != nil {
		return err
	}
	if !containedPath(baseAbs, want) || !containedPath(baseAbs, got) {
		return fmt.Errorf("workspace resolves outside sessions dir")
	}
	if !samePath(got, want) {
		return fmt.Errorf("workspace %q does not match run folder", workspace)
	}
	return nil
}

// verifyRecoveryOwnership applies the same strict run/profile/path binding
// as verifyOwnership, while allowing the owned workspace to be absent. A
// previous cleanup may have removed the workspace before a transient profile
// deletion failure; the journal must remain recoverable in that state.
func verifyRecoveryOwnership(sessionsDir, runID, profile, workspace string) error {
	if err := validRunID(runID); err != nil {
		return err
	}
	if profile != profilePrefix+runID {
		return fmt.Errorf("profile %q is not run-bound", profile)
	}
	if err := ValidProfileName(profile); err != nil {
		return err
	}
	baseAbs, err := filepath.Abs(sessionsDir)
	if err != nil {
		return err
	}
	if err := validatePlainDirectory(baseAbs); err != nil {
		return fmt.Errorf("sessions dir is not controller-owned: %w", err)
	}
	workspaceAbs, err := filepath.Abs(workspace)
	if err != nil {
		return err
	}
	runPath := filepath.Join(baseAbs, runID)
	if !containedPath(baseAbs, runPath) || !samePath(workspaceAbs, runPath) {
		return fmt.Errorf("workspace does not match run folder")
	}
	if info, lerr := os.Lstat(workspaceAbs); os.IsNotExist(lerr) {
		return nil
	} else if lerr != nil {
		return lerr
	} else if info.Mode()&os.ModeSymlink != 0 || pathHasReparse(info) || !info.IsDir() {
		return fmt.Errorf("workspace is not a plain controller-owned directory")
	}
	return verifyOwnership(baseAbs, runID, profile, workspaceAbs)
}

// validRunID is intentionally narrower than a general filename. Run IDs
// originate in the controller and are later used to select cleanup records;
// accepting dots, separators, or control characters would turn a journal
// record into a path selector.
func validRunID(id string) error {
	if id == "" || len(id) > 48 {
		return fmt.Errorf("run id length out of range")
	}
	for _, r := range id {
		if r > unicode.MaxASCII || !(r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return fmt.Errorf("run id contains forbidden character")
		}
	}
	return nil
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// JobLimits is the requested job policy. Zero CPURatePercent skips CPU
// control; everything else must apply.
type JobLimits struct {
	JobMemoryMB    uint64
	MaxProcesses   uint32
	CPURatePercent uint32 // 1..100 hard cap, 0 = skip
	DiskBudgetMB   uint64 // sampled workspace budget; not a filesystem quota
}

// DefaultJobLimits is the N2 starting policy: 2 GB job memory,
// 64 processes, no CPU cap (best-effort knob, SKU-dependent).
func DefaultJobLimits() JobLimits {
	return JobLimits{JobMemoryMB: 2048, MaxProcesses: 64, CPURatePercent: 50, DiskBudgetMB: 4096}
}

// DefaultResourceLimits is the declared budget attached to native
// attestations (W2): job memory from the job policy, wall/output
// overridden per contract at verify time. CPU is host capacity
// reference and disk is a declared budget — both disclosed in reports,
// see the amendment honesty rule (no hard quota claims).
func DefaultResourceLimits() worker.ResourceLimits {
	return worker.ResourceLimits{
		CPUCores:       2,
		MemoryMB:       int(DefaultJobLimits().JobMemoryMB),
		DiskMB:         4096,
		WallSeconds:    600,
		MaxOutputBytes: 20 << 20,
	}
}

// NativeAttestation issues the controller-side attestation for the
// native backend (W2): kind and digests are fixed markers describing
// the no-image model, limits come from the caller, and Attested is
// true only when the native probe passes. Only the controller (our
// code, never the workload) may issue it — see worker.Attestation.
func NativeAttestation(limits worker.ResourceLimits) worker.Attestation {
	sup := ProbeSupport()
	raw, _ := json.Marshal(limits)
	sum := sha256.Sum256(raw)
	imageSum := sha256.Sum256([]byte("repoproof-native-appcontainer"))
	return worker.Attestation{
		WorkerKind:   "appcontainer-native",
		ImageDigest:  "sha256:" + hex.EncodeToString(imageSum[:]),
		PolicyDigest: "sha256:" + hex.EncodeToString(sum[:]),
		Network:      worker.NetworkGuestOnly,
		HostMounts:   0,
		Privileged:   false,
		Limits:       limits,
		// A DLL capability probe is not a security attestation. Keep the
		// production gate closed until the independent native lab receipt
		// (12 scenarios + policy measurement) is shipped and verified.
		Attested: sup.Supported && nativeLabAttestationReady,
	}
}

const nativeLabAttestationReady = false

// containedPath reports whether target resolves strictly inside base.
func containedPath(base, target string) bool {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "."
}
