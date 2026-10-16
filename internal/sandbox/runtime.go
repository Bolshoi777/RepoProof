// Runtime resolution (N3): locate known language runtimes without
// executing repository code. Only explicit directories are searched —
// never PATH fishing (avoids user shims) — and only a fixed `--version`
// probe runs, against vendor binaries, never repo content.
//
// Layout of a portable runtime root:
//
//	<runtimes>/<kind>.json              manifest {kind, exe, version}
//	<runtimes>/<kind>/...               the runtime files (read-only)
//
// Absent runtimes resolve to OriginNone: callers must map that to
// UNSUPPORTED, never to host execution.
package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Runtime kinds supported for dynamic verification in v1.
const (
	RuntimePython = "python"
	RuntimeNode   = "node"
	RuntimeCmd    = "cmd" // built-in chain proof, not a language runtime
)

// Runtime origins: portable (managed copy), system (explicit known
// location), none (absent -> UNSUPPORTED).
const (
	OriginPortable = "portable"
	OriginSystem   = "system"
	OriginNone     = "none"
)

// Runtime is a resolved interpreter.
type Runtime struct {
	Kind    string `json:"kind"`
	ExePath string `json:"exe_path,omitempty"`
	Version string `json:"version,omitempty"`
	Origin  string `json:"origin"`
}

// manifest is the portable-root descriptor. Files counts extracted
// files; resolveCache verifies it, so interrupted provisions never
// pass as complete.
type manifest struct {
	Kind    string `json:"kind"`
	Exe     string `json:"exe"`
	Version string `json:"version"`
	Files   int    `json:"files"`
}

// Resolve looks for kind in roots (portable manifests), then in
// systemDirs (explicit files). Empty result has Origin "none".
// With probe=true the binary is run once with fixed ["--version"]
// (vendor code, never repo code); probe=false trusts manifest+file.
func Resolve(ctx context.Context, kind string, roots, systemDirs []string, probe bool) Runtime {
	for _, root := range roots {
		if rt, ok := resolvePortable(kind, root); ok {
			if probe {
				if v, err := probeVersion(ctx, rt.ExePath); err != nil {
					continue
				} else if rt.Version == "" {
					rt.Version = v
				}
			}
			return rt
		}
	}
	for _, dir := range systemDirs {
		for _, name := range exeNames(kind) {
			p := filepath.Join(dir, name)
			if st, err := os.Stat(p); err != nil || st.IsDir() {
				continue
			}
			rt := Runtime{Kind: kind, ExePath: p, Origin: OriginSystem}
			if probe {
				v, err := probeVersion(ctx, p)
				if err != nil {
					continue
				}
				rt.Version = v
			}
			return rt
		}
	}
	return Runtime{Kind: kind, Origin: OriginNone}
}

func resolvePortable(kind, root string) (Runtime, bool) {
	raw, err := os.ReadFile(filepath.Join(root, kind+".json"))
	if err != nil {
		return Runtime{}, false
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil || m.Kind != kind || m.Exe == "" {
		return Runtime{}, false
	}
	if err := VerifyRoot(root, kind, m); err != nil {
		return Runtime{}, false
	}
	exe := m.Exe
	if !filepath.IsAbs(exe) {
		exe = filepath.Join(root, exe)
	}
	if st, err := os.Stat(exe); err != nil || st.IsDir() {
		return Runtime{}, false
	}
	return Runtime{Kind: kind, ExePath: exe, Version: m.Version, Origin: OriginPortable}, true
}

// VerifyCachedRoot validates a cache entry by its own manifest:
// parseable manifest, completion sentinel, and matching file count.
func VerifyCachedRoot(root, kind string) error {
	raw, err := os.ReadFile(filepath.Join(root, kind+".json"))
	if err != nil {
		return err
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if m.Kind != kind || m.Exe == "" {
		return fmt.Errorf("bad manifest for %s", kind)
	}
	return VerifyRoot(root, kind, m)
}

// VerifyRoot rejects incomplete runtimes: missing .complete sentinel
// or file-count mismatch (interrupted provision or later damage).
func VerifyRoot(root, kind string, m manifest) error {
	if !safeRuntimeRelPath(m.Exe) {
		return fmt.Errorf("runtime %s has unsafe executable path", kind)
	}
	exe := filepath.Join(root, filepath.FromSlash(m.Exe))
	if !containedPath(root, exe) {
		return fmt.Errorf("runtime %s executable escapes root", kind)
	}
	if _, err := os.Stat(filepath.Join(root, ".complete")); err != nil {
		return fmt.Errorf("runtime %s incomplete (no completion record)", kind)
	}
	n, err := countFiles(root, kind+".json")
	if err != nil {
		return err
	}
	if m.Files <= 0 || n != m.Files {
		return fmt.Errorf("runtime %s file count %d != recorded %d", kind, n, m.Files)
	}
	return nil
}

func exeNames(kind string) []string {
	switch kind {
	case RuntimePython:
		return []string{"python.exe"}
	case RuntimeNode:
		return []string{"node.exe"}
	default:
		return nil
	}
}

// probeVersion runs the vendor binary with a fixed argv and a short
// timeout, returning the first output line.
func probeVersion(ctx context.Context, exe string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// NOTE: direct process launch, no shell, fixed argv. Vendor binary
	// only; the sandbox package never launches repository content.
	out, err := exec.CommandContext(ctx, exe, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("version probe failed for %s: %w", exe, err)
	}
	line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	if line == "" {
		return "", fmt.Errorf("empty version output for %s", exe)
	}
	if len(line) > 120 {
		line = line[:120]
	}
	return line, nil
}
