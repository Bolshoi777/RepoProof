// Package policy implements explicit execute authorization (G2-02,
// RP-006): no approval, no execution. Authorization binds three things
// together — a controller attestation, a candidate plan, and a human
// approval record — and denies on any mismatch.
//
// Deny is fail-closed and accumulates every reason so the operator
// sees the full picture, not just the first failure. Absence of an
// approval file is itself a denial, including in CI: there is no
// implicit opt-in, no environment-variable bypass.
//
// This package grants permission only; it never executes anything.
// Actual execution additionally requires an attested backend, which
// does not exist yet (NullWorker, G2-01).
package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/repoproof/repoproof/internal/planner"
	"github.com/repoproof/repoproof/internal/worker"
)

// Approval is the human opt-in record. JSON-serializable so it can be
// stored, reviewed and passed as a file. Forbidden capabilities cannot
// be granted through it: AllowHostMounts/AllowPrivileged set to true
// make the approval itself invalid.
type Approval struct {
	Version               string     `json:"version"`
	PlanFingerprint       string     `json:"plan_fingerprint"`
	ContractFingerprint   string     `json:"contract_fingerprint,omitempty"`
	DependencyFingerprint string     `json:"dependency_fingerprint,omitempty"`
	Commit                *string    `json:"commit"`
	Statement             string     `json:"statement"`
	AcknowledgedReasons   []string   `json:"acknowledged_reasons"`
	ApprovedNetwork       string     `json:"approved_network"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty"`
	AllowHostMounts       bool       `json:"allow_host_mounts"`
	AllowPrivileged       bool       `json:"allow_privileged"`
}

const ApprovalTTL = 24 * time.Hour

// NewExpiry creates the bounded validity window used by generated approval
// records. Callers should pass UTC time so JSON is deterministic.
func NewExpiry(now time.Time) *time.Time {
	exp := now.UTC().Add(ApprovalTTL)
	return &exp
}

// DenyError explains an authorization refusal. Non-nil means execution
// is denied; the caller maps it to BLOCKED_SECURITY or a policy exit.
type DenyError struct {
	Reasons []string
}

func (e *DenyError) Error() string {
	return "DENIED: " + strings.Join(e.Reasons, "; ")
}

// Authorize binds attestation, plan and approval. Order: worker first
// (no backend, no discussion), then approval presence, then every
// binding check. Pure function, no I/O, no execution.
func Authorize(att worker.Attestation, plan *planner.Plan, approval *Approval, contractFingerprint ...string) error {
	reasons := []string{}

	if err := worker.Gate(att); err != nil {
		reasons = append(reasons, "worker gate: "+err.Error())
	}
	if approval == nil {
		reasons = append(reasons, "explicit approval required: none provided")
		return &DenyError{Reasons: reasons}
	}

	if approval.Version != "1" {
		reasons = append(reasons, "approval version must be \"1\"")
	}
	if strings.TrimSpace(approval.Statement) == "" {
		reasons = append(reasons, "approval statement must not be empty")
	}
	if approval.ExpiresAt == nil {
		reasons = append(reasons, "approval expiry is required")
	} else if !time.Now().UTC().Before(approval.ExpiresAt.UTC()) {
		reasons = append(reasons, "approval has expired")
	}
	if approval.PlanFingerprint == "" || approval.PlanFingerprint != plan.Fingerprint {
		reasons = append(reasons, "approval does not match plan fingerprint: stale or foreign approval")
	}
	if len(contractFingerprint) > 0 {
		want := contractFingerprint[0]
		if want == "" || approval.ContractFingerprint == "" || approval.ContractFingerprint != want {
			reasons = append(reasons, "approval does not match proof contract fingerprint: stale or replaced contract")
		}
	}
	if len(contractFingerprint) > 1 && contractFingerprint[1] != "" {
		want := contractFingerprint[1]
		if approval.DependencyFingerprint == "" || approval.DependencyFingerprint != want {
			reasons = append(reasons, "approval does not match dependency fingerprint: requirements or runtime changed")
		}
	}
	if !equalCommit(approval.Commit, plan.Commit) {
		reasons = append(reasons, "approval commit does not match plan commit")
	}
	if approval.AllowHostMounts {
		reasons = append(reasons, "approval requests forbidden capability: host mounts")
	}
	if approval.AllowPrivileged {
		reasons = append(reasons, "approval requests forbidden capability: privileged execution")
	}
	if approval.ApprovedNetwork == "" {
		reasons = append(reasons, "approval must name an explicit network mode")
	} else if worker.NetworkMode(approval.ApprovedNetwork) != att.Network {
		reasons = append(reasons, fmt.Sprintf(
			"approval network %q does not match attested %q", approval.ApprovedNetwork, att.Network))
	}
	acked := map[string]bool{}
	for _, r := range approval.AcknowledgedReasons {
		acked[r] = true
	}
	for _, need := range plan.ReviewReasons {
		if !acked[need] {
			reasons = append(reasons, fmt.Sprintf("review reason not acknowledged: %q", need))
		}
	}

	if len(reasons) > 0 {
		return &DenyError{Reasons: reasons}
	}
	return nil
}

func equalCommit(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
