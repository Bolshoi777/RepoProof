// Package replay pins verified results to their environment (G3-06,
// RP-016): a canonical environment fingerprint recorded with every
// verdict, and an explicit field-by-field comparison on replay. Any
// mismatch refuses silent reuse with a named warning — a stale image,
// a swapped policy or a different runtime never passes as the same
// environment. Pure logic, no execution.
package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/repoproof/repoproof/internal/version"
	"github.com/repoproof/repoproof/internal/worker"
)

// Fingerprint is the recorded environment identity.
type Fingerprint struct {
	WorkerKind   string            `json:"worker_kind"`
	ImageDigest  string            `json:"image_digest"`
	PolicyDigest string            `json:"policy_digest"`
	Network      string            `json:"network_mode"`
	OS           string            `json:"os"`
	Arch         string            `json:"arch"`
	OSBuild      string            `json:"os_build,omitempty"`
	Runtimes     map[string]string `json:"runtimes,omitempty"`
	AppVersion   string            `json:"app_version"`
}

// Capture builds the fingerprint of the current environment from an
// attestation plus measured runtime versions. Only provided values
// are recorded: nothing is guessed or defaulted.
func Capture(att worker.Attestation, osBuild string, runtimes map[string]string) Fingerprint {
	rt := map[string]string{}
	for k, v := range runtimes {
		rt[k] = v
	}
	return Fingerprint{
		WorkerKind:   att.WorkerKind,
		ImageDigest:  att.ImageDigest,
		PolicyDigest: att.PolicyDigest,
		Network:      string(att.Network),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		OSBuild:      osBuild,
		Runtimes:     rt,
		AppVersion:   version.ModuleVersion,
	}
}

// Digest returns the canonical sha256 of the fingerprint. Go's JSON
// marshaler sorts map keys, so this is deterministic.
func (f Fingerprint) Digest() (string, error) {
	raw, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// Compare lists every field where current differs from recorded.
// Empty means identical environments. Order is fixed for stable output.
func Compare(recorded, current Fingerprint) []string {
	diffs := []string{}
	add := func(format string, args ...any) {
		diffs = append(diffs, fmt.Sprintf(format, args...))
	}
	if recorded.WorkerKind != current.WorkerKind {
		add("worker_kind changed: %q -> %q", recorded.WorkerKind, current.WorkerKind)
	}
	if recorded.ImageDigest != current.ImageDigest {
		add("image_digest changed: environment is not the verified one")
	}
	if recorded.PolicyDigest != current.PolicyDigest {
		add("policy_digest changed: limits unverifiable against the verified run")
	}
	if recorded.Network != current.Network {
		add("network_mode changed: %q -> %q", recorded.Network, current.Network)
	}
	if recorded.OS != current.OS || recorded.Arch != current.Arch {
		add("platform changed: %s/%s -> %s/%s", recorded.OS, recorded.Arch, current.OS, current.Arch)
	}
	if recorded.OSBuild != current.OSBuild {
		add("os_build changed: %q -> %q", recorded.OSBuild, current.OSBuild)
	}
	keys := map[string]bool{}
	for k := range recorded.Runtimes {
		keys[k] = true
	}
	for k := range current.Runtimes {
		keys[k] = true
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if recorded.Runtimes[k] != current.Runtimes[k] {
			add("runtime %q changed: %q -> %q", k, recorded.Runtimes[k], current.Runtimes[k])
		}
	}
	if recorded.AppVersion != current.AppVersion {
		add("app_version changed: %q -> %q", recorded.AppVersion, current.AppVersion)
	}
	return diffs
}

// CheckReplay decides whether a recorded verdict may be reused in the
// current environment. Any difference refuses with explicit warnings;
// tampered digests (recomputed mismatch) are an error, not a warning.
func CheckReplay(recorded Fingerprint, recordedDigest string, current Fingerprint) (bool, []string, error) {
	recomputed, err := recorded.Digest()
	if err != nil {
		return false, nil, err
	}
	if recomputed != strings.ToLower(strings.TrimSpace(recordedDigest)) {
		return false, nil, fmt.Errorf("replay: recorded fingerprint digest mismatch (tampered record)")
	}
	if diffs := Compare(recorded, current); len(diffs) > 0 {
		out := append([]string{"environment changed since verification: re-verification required"}, diffs...)
		return false, out, nil
	}
	return true, nil, nil
}
