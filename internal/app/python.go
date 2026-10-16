package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/orchestrate"
	"github.com/repoproof/repoproof/internal/planner"
	"github.com/repoproof/repoproof/internal/pydeps"
	"github.com/repoproof/repoproof/internal/sandbox"
)

// CacheDirDefault is the opt-in persistent runtime cache. It exists
// only because the operator ran a verification (never pre-created),
// holds pinned portable runtimes with manifests, and is removed by
// deleting the folder — documented in report limitations.
func CacheDirDefault() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "repoproof", "runtimes")
}

// EnsurePython resolves portable CPython from the cache, provisioning
// the pinned distribution once when absent. The digest pin makes a
// hostile cache entry fail loudly instead of executing.
// Returns the runtime plus its root dir (for staging copies).
func EnsurePython(ctx context.Context, cacheDir string) (sandbox.Runtime, string, error) {
	if cacheDir == "" {
		cacheDir = CacheDirDefault()
	}
	if rt, root := resolveCache(cacheDir, sandbox.RuntimePython); rt.Origin != sandbox.OriginNone {
		return rt, root, nil
	}
	prov, err := sandbox.Provision(ctx, sandbox.PinnedPython(), cacheDir)
	if err != nil {
		return sandbox.Runtime{}, "", fmt.Errorf("provision python: %w", err)
	}
	return prov.Runtime, prov.Root, nil
}

func resolveCache(cacheDir, kind string) (sandbox.Runtime, string) {
	none := sandbox.Runtime{Kind: kind, Origin: sandbox.OriginNone}
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return none, ""
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		root := filepath.Join(cacheDir, e.Name())
		raw, err := os.ReadFile(filepath.Join(root, kind+".json"))
		if err != nil {
			continue
		}
		var m struct {
			Kind    string `json:"kind"`
			Exe     string `json:"exe"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(raw, &m); err != nil || m.Kind != kind || m.Exe == "" {
			continue
		}
		if err := sandbox.VerifyCachedRoot(root, kind); err != nil {
			continue
		}
		exe := m.Exe
		if !filepath.IsAbs(exe) {
			exe = filepath.Join(root, exe)
		}
		if st, err := os.Stat(exe); err != nil || st.IsDir() {
			continue
		}
		return sandbox.Runtime{Kind: kind, ExePath: exe, Version: m.Version, Origin: sandbox.OriginPortable}, root
	}
	return none, ""
}

// copyDirRecursive copies src into dst (production helper for staging
// runtimes and wheels into session workspaces, which Finalize removes).
func copyDirRecursive(src, dst string) error {
	if info, err := os.Lstat(src); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runtime source is not a plain directory: %s", src)
	}
	root, err := filepath.EvalSymlinks(src)
	if err != nil {
		return err
	}
	return copyDirRecursiveWithin(root, src, dst)
}

func copyDirRecursiveWithin(root, src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, e := range entries {
		s, d := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		info, err := os.Lstat(s)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in staged runtime: %s", s)
		}
		resolved, err := filepath.EvalSymlinks(s)
		if err != nil || !pathWithinCanonical(root, resolved) || !sameRuntimePath(s, resolved) {
			return fmt.Errorf("staged runtime path escapes root: %s", s)
		}
		if e.IsDir() {
			if err := copyDirRecursiveWithin(root, s, d); err != nil {
				return err
			}
			continue
		}
		f, err := openRuntimeSource(s)
		if err != nil {
			return err
		}
		raw, err := io.ReadAll(io.LimitReader(f, 512<<20+1))
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if int64(len(raw)) > 512<<20 {
			return fmt.Errorf("runtime file exceeds copy limit: %s", s)
		}
		if err := os.WriteFile(d, raw, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func pathWithinCanonical(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// StageWheels parses target/requirements.txt (exact pins only) and
// stages digest-pinned wheels into workDir. (nil, nil) when the project
// has no requirements file: nothing to install is not an error.
func StageWheels(ctx context.Context, target, workDir string) ([]string, error) {
	raw, err := os.ReadFile(filepath.Join(target, "requirements.txt"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return stageWheelsBytes(ctx, raw, workDir)
}

func stageWheelsBytes(ctx context.Context, raw []byte, workDir string) ([]string, error) {
	pins, err := pydeps.ParseRequirements(raw)
	if err != nil {
		return nil, err
	}
	return pydeps.Stage(ctx, "", pins, filepath.Join(workDir, "wheels"))
}

// depsBundle carries auto-staged dependencies into a run.
type depsBundle struct {
	OnSession          func(sandbox.Session) ([]string, error)
	Prologue           func(sandbox.Session) []orchestrate.StepRequest
	Note               string
	Cleanup            func()
	RuntimeFingerprint string
}

func fingerprintTree(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	root = abs
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	var total int64
	var count int
	h := sha256.New()
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		// pip's normal install target is runtime/Lib/site-packages and is
		// intentionally mutable during the install prologue. Interpreter,
		// stdlib, and launcher files remain covered by this digest.
		for _, part := range strings.Split(strings.ToLower(relSlash), "/") {
			if part == "site-packages" {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("runtime symlink/reparse refused: %s", path)
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		if !containedRuntimePath(canonicalRoot, resolved) || !sameRuntimePath(path, resolved) {
			return fmt.Errorf("runtime reparse refused: %s", path)
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("runtime special file refused: %s", path)
		}
		count++
		if count > 1_000_000 {
			return fmt.Errorf("runtime file count limit exceeded")
		}
		info, err := d.Info()
		if err != nil || info.Size() < 0 || info.Size() > (512<<20)-total {
			return fmt.Errorf("runtime size limit exceeded")
		}
		total += info.Size()
		h.Write([]byte(relSlash))
		h.Write([]byte{0})
		var sizeBuf [8]byte
		for i := uint(0); i < 8; i++ {
			sizeBuf[i] = byte(uint64(info.Size()) >> (8 * i))
		}
		h.Write(sizeBuf[:])
		f, err := openRuntimeSource(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(h, io.LimitReader(f, info.Size()+1))
		cerr := f.Close()
		if err != nil {
			return err
		}
		return cerr
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func containedRuntimePath(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func sameRuntimePath(a, b string) bool {
	if os.PathSeparator == '\\' {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// autoDeps prepares python dependency installation for a run: resolved
// runtime + staged wheels, copied into the session workspace after
// Prepare, installed via a recorded prologue step before contract
// steps. Missing/broken deps are hard errors: running without declared
// dependencies would produce false failures, never silent skips.
// Returns nil only when provisioning is explicitly disabled or the stack is
// outside Python. Python projects always receive the pinned runtime, even
// when they have no requirements file.
// p.Target must be a local materialized directory (see resolveTarget):
// raw URL strings never reach here.
func autoDeps(ctx context.Context, p VerifyParams, plan *planner.Plan) (*depsBundle, error) {
	return autoDepsSnapshot(ctx, p, plan, nil)
}

func autoDepsSnapshot(ctx context.Context, p VerifyParams, plan *planner.Plan, snapshot *inspector.Snapshot) (*depsBundle, error) {
	if p.NoProvision || plan.Stack != "python" {
		return nil, nil
	}
	var reqRaw []byte
	var err error
	if snapshot != nil {
		hasRequirements := false
		for _, entry := range snapshot.Files {
			if entry.Path == "requirements.txt" {
				hasRequirements = true
				break
			}
		}
		if hasRequirements {
			reqRaw, err = inspector.ReadVerifiedFile(*snapshot, p.Target, "requirements.txt")
		}
	} else {
		reqRaw, err = os.ReadFile(filepath.Join(p.Target, "requirements.txt"))
	}
	if err != nil {
		if os.IsNotExist(err) {
			reqRaw = nil
		} else {
			return nil, fmt.Errorf("deps: %w", err)
		}
	}
	rt, rtRoot, err := EnsurePython(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("deps: %w", err)
	}
	stageTmp, err := os.MkdirTemp("", "repoproof-stage-")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(stageTmp) }
	var wheels []string
	resolvedFP := ""
	if len(reqRaw) > 0 {
		pins, perr := pydeps.ParseRequirements(reqRaw)
		if perr != nil {
			cleanup()
			return nil, fmt.Errorf("deps: %w", perr)
		}
		resolved, rerr := pydeps.Resolve(ctx, "", pins)
		if rerr != nil {
			cleanup()
			return nil, fmt.Errorf("deps: %w", rerr)
		}
		resolvedFP = pydeps.FingerprintResolved(resolved)
		wheels, err = pydeps.StageResolved(ctx, resolved, stageTmp)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("deps: %w", err)
		}
	}
	actualFP, ferr := dependencyFingerprintForRequirements(p.Target, reqRaw, resolvedFP)
	if ferr != nil {
		cleanup()
		return nil, fmt.Errorf("deps fingerprint: %w", ferr)
	}
	if p.ExpectedDependencyFingerprint != "" && actualFP != p.ExpectedDependencyFingerprint {
		cleanup()
		return nil, fmt.Errorf("deps: resolved artifacts changed after approval")
	}
	relExe, err := filepath.Rel(rtRoot, rt.ExePath)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("deps: %w", err)
	}
	relDir := filepath.Dir(relExe)
	runtimeFingerprint, err := fingerprintTree(rtRoot)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("deps: runtime fingerprint: %w", err)
	}
	b := &depsBundle{Cleanup: cleanup, RuntimeFingerprint: runtimeFingerprint}
	b.OnSession = func(s sandbox.Session) ([]string, error) {
		if err := copyDirRecursive(rtRoot, filepath.Join(s.Workspace, "rt")); err != nil {
			return nil, fmt.Errorf("stage runtime: %w", err)
		}
		if len(wheels) > 0 {
			if err := copyDirRecursive(filepath.Join(stageTmp, "wheels"), filepath.Join(s.Workspace, "wheels")); err != nil {
				return nil, fmt.Errorf("stage wheels: %w", err)
			}
		}
		if len(reqRaw) > 0 {
			if err := os.WriteFile(filepath.Join(s.Workspace, "requirements.txt"), reqRaw, 0o644); err != nil {
				return nil, err
			}
		}
		return []string{filepath.Join(s.Workspace, "rt", relDir)}, nil
	}
	b.Prologue = func(s sandbox.Session) []orchestrate.StepRequest {
		if len(wheels) == 0 {
			return nil
		}
		pyExe := filepath.Join(s.Workspace, "rt", relExe)
		return []orchestrate.StepRequest{{
			ID:  "deps-install",
			Exe: pyExe,
			Args: []string{"-m", "pip", "install", "--no-index", "--find-links",
				filepath.Join(s.Workspace, "wheels"), "-r",
				filepath.Join(s.Workspace, "requirements.txt")},
			Timeout: 5 * time.Minute,
		}}
	}
	b.Note = fmt.Sprintf("deps auto-staged: %d wheel(s) from PyPI pins, runtime %s from %s",
		len(wheels), rt.Version, CacheDirDefault())
	return b, nil
}
