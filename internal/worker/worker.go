// Package worker defines the isolated execution boundary (G2-01,
// RP-007): the Executor interface, controller attestation and the
// fail-closed Gate. No implementation in this slice runs guest code:
// NullWorker is the only Executor and it refuses everything.
//
// Trust rule (docs/03_SANDBOX_SECURITY.md): attestation is issued by
// the trusted controller side, never self-reported by the workload.
// Until a lab-attested VM backend exists (G2 gate), every execute
// path must resolve to BLOCKED_SECURITY.
package worker

import (
	"context"
	"errors"
	"strings"
)

// ErrNoWorker is returned when no attested backend exists. It is a
// fail-closed signal, never a cue to fall back to host execution:
// host shell fallback is forbidden unconditionally.
var ErrNoWorker = errors.New("no attested isolated worker: execute disabled")

// NetworkMode mirrors the report schema contract.
type NetworkMode string

const (
	NetworkGuestOnly  NetworkMode = "guest-only"
	NetworkRestricted NetworkMode = "restricted-install"
	NetworkDisabled   NetworkMode = "disabled"
	NetworkUnknown    NetworkMode = "unknown"
)

// ResourceLimits mirrors the initial policy examples in
// docs/03_SANDBOX_SECURITY.md section 6. Values are data for the
// future backend to enforce; nothing enforces them yet.
type ResourceLimits struct {
	CPUCores       int   `json:"cpu_cores"`
	MemoryMB       int   `json:"memory_mb"`
	DiskMB         int   `json:"disk_mb"`
	WallSeconds    int   `json:"wall_seconds"`
	MaxOutputBytes int64 `json:"max_output_bytes"`
}

// DefaultLimits returns the documented initial policy example.
func DefaultLimits() ResourceLimits {
	return ResourceLimits{
		CPUCores:       2,
		MemoryMB:       2048,
		DiskMB:         4096,
		WallSeconds:    600,
		MaxOutputBytes: 20 << 20,
	}
}

// Attestation is the controller-issued capability statement of one
// worker. Every field must be observed, never defaulted: empty
// digests or unknown modes fail the Gate. Only the trusted controller
// side may construct one; Gate checks content, not provenance, so a
// workload must never be in a position to issue its own attestation.
type Attestation struct {
	WorkerKind   string         `json:"worker_kind"`
	ImageDigest  string         `json:"image_digest"`
	PolicyDigest string         `json:"policy_digest"`
	Network      NetworkMode    `json:"network_mode"`
	HostMounts   int            `json:"host_mounts"`
	Privileged   bool           `json:"privileged"`
	Limits       ResourceLimits `json:"limits"`
	Attested     bool           `json:"attested"`
}

// Executor is the execution boundary. Step streaming (RunStep per
// docs/10_PROTOCOL_AND_LIMITS.md) lands here in G2-03 with a real
// backend; every implementation MUST run guest-side only and MUST
// NOT offer host shell access.
type Executor interface {
	Attest(ctx context.Context) (Attestation, error)
	Destroy(ctx context.Context, id string) error
}

// NullWorker is the only Executor until the G2 lab attests a real
// backend. It refuses everything without side effects.
type NullWorker struct{}

func (NullWorker) Attest(context.Context) (Attestation, error) {
	return Attestation{WorkerKind: "none", Network: NetworkDisabled}, ErrNoWorker
}

func (NullWorker) Destroy(context.Context, string) error {
	return ErrNoWorker
}

// BlockError explains a Gate refusal. Non-nil means BLOCKED_SECURITY.
type BlockError struct {
	Reasons []string
}

func (e *BlockError) Error() string {
	return "BLOCKED_SECURITY: " + strings.Join(e.Reasons, "; ")
}

// Gate is the fail-closed policy check: a worker executes only with
// controller attestation, zero host mounts, no privileges, a known
// network mode, pinned digests and positive resource limits.
// Pure function, no I/O, no execution.
func Gate(a Attestation) error {
	reasons := []string{}
	if !a.Attested {
		reasons = append(reasons, "worker not attested by controller")
	}
	if a.WorkerKind == "" || a.WorkerKind == "none" {
		reasons = append(reasons, "no worker backend provisioned")
	}
	if !validDigest(a.ImageDigest) {
		reasons = append(reasons, "image digest must be sha256:<64 hex>: workload origin unpinned")
	}
	if !validDigest(a.PolicyDigest) {
		reasons = append(reasons, "policy digest must be sha256:<64 hex>: limits unverifiable")
	}
	if a.HostMounts != 0 {
		reasons = append(reasons, "host mounts must be 0")
	}
	if a.Privileged {
		reasons = append(reasons, "privileged execution forbidden")
	}
	switch a.Network {
	case NetworkGuestOnly, NetworkRestricted, NetworkDisabled:
	default:
		reasons = append(reasons, "network mode unknown or unset")
	}
	l := a.Limits
	if l.CPUCores <= 0 || l.MemoryMB <= 0 || l.DiskMB <= 0 || l.WallSeconds <= 0 || l.MaxOutputBytes <= 0 {
		reasons = append(reasons, "resource limits missing or non-positive")
	}
	if len(reasons) > 0 {
		return &BlockError{Reasons: reasons}
	}
	return nil
}

func validDigest(s string) bool {
	if len(s) != len("sha256:")+64 || !strings.HasPrefix(strings.ToLower(s), "sha256:") {
		return false
	}
	for _, r := range s[len("sha256:"):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
