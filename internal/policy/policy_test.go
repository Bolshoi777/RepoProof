package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/repoproof/repoproof/internal/inspector"
	"github.com/repoproof/repoproof/internal/planner"
	"github.com/repoproof/repoproof/internal/worker"
)

func validAttestation() worker.Attestation {
	return worker.Attestation{
		WorkerKind:   "test-vm",
		ImageDigest:  "sha256:" + strings.Repeat("a", 64),
		PolicyDigest: "sha256:" + strings.Repeat("b", 64),
		Network:      worker.NetworkGuestOnly,
		HostMounts:   0,
		Privileged:   false,
		Limits:       worker.DefaultLimits(),
		Attested:     true,
	}
}

func mkProject(t *testing.T, readme string) *planner.Plan {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := inspector.Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	return planner.Build(&rep.Snapshot)
}

func approvalFor(p *planner.Plan) *Approval {
	return &Approval{
		Version:             "1",
		PlanFingerprint:     p.Fingerprint,
		Commit:              p.Commit,
		Statement:           "reviewed test plan, approve isolated run",
		AcknowledgedReasons: append([]string{}, p.ReviewReasons...),
		ApprovedNetwork:     string(worker.NetworkGuestOnly),
		ExpiresAt:           NewExpiry(time.Now().UTC()),
	}
}

// TestAbsenceOfApprovalDenies is the RP-006 core: no approval record,
// no execution — even with a perfectly attested worker and clean plan.
func TestAbsenceOfApprovalDenies(t *testing.T) {
	p := mkProject(t, "```sh\nnpm start\n```\n")
	if p.NeedsReview {
		t.Fatalf("fixture plan should be clean: %v", p.ReviewReasons)
	}
	err := Authorize(validAttestation(), p, nil)
	if err == nil {
		t.Fatal("expected denial without approval")
	}
	var derr *DenyError
	if !errors.As(err, &derr) {
		t.Fatalf("expected *DenyError, got %T", err)
	}
	if !strings.Contains(err.Error(), "explicit approval required") {
		t.Fatalf("error %q hides the reason", err)
	}
}

func TestHappyPathAuthorizes(t *testing.T) {
	p := mkProject(t, "```sh\nnpm start\n```\n")
	if err := Authorize(validAttestation(), p, approvalFor(p)); err != nil {
		t.Fatalf("valid binding denied: %v", err)
	}
}

func TestApprovalExpiryIsEnforced(t *testing.T) {
	p := mkProject(t, "```sh\nnpm start\n```\n")
	ap := approvalFor(p)
	past := time.Now().UTC().Add(-time.Minute)
	ap.ExpiresAt = &past
	if err := Authorize(validAttestation(), p, ap); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired approval accepted: %v", err)
	}
	ap.ExpiresAt = nil
	if err := Authorize(validAttestation(), p, ap); err == nil || !strings.Contains(err.Error(), "expiry is required") {
		t.Fatalf("missing approval expiry accepted: %v", err)
	}
}

func TestContractFingerprintBinding(t *testing.T) {
	p := mkProject(t, "```sh\nnpm start\n```\n")
	ap := approvalFor(p)
	ap.ContractFingerprint = "sha256-contract-a"
	ap.DependencyFingerprint = "sha256-deps-a"
	if err := Authorize(validAttestation(), p, ap, "sha256-contract-a", "sha256-deps-a"); err != nil {
		t.Fatalf("matching contract fingerprint denied: %v", err)
	}
	if err := Authorize(validAttestation(), p, ap, "sha256-contract-b", "sha256-deps-a"); err == nil || !strings.Contains(err.Error(), "proof contract fingerprint") {
		t.Fatalf("stale contract fingerprint accepted: %v", err)
	}
	if err := Authorize(validAttestation(), p, ap, "sha256-contract-a", "sha256-deps-b"); err == nil || !strings.Contains(err.Error(), "dependency fingerprint") {
		t.Fatalf("stale dependency fingerprint accepted: %v", err)
	}
	ap.ContractFingerprint = ""
	if err := Authorize(validAttestation(), p, ap, "sha256-contract-a", "sha256-deps-a"); err == nil {
		t.Fatal("missing contract fingerprint accepted")
	}
}

func TestWorkerFailurePropagates(t *testing.T) {
	p := mkProject(t, "```sh\nnpm start\n```\n")
	att := validAttestation()
	att.Attested = false
	err := Authorize(att, p, approvalFor(p))
	if err == nil || !strings.Contains(err.Error(), "worker gate") {
		t.Fatalf("expected worker-gate denial, got %v", err)
	}
}

func TestDenyTable(t *testing.T) {
	base := mkProject(t, "```sh\nnpm start\n```\n")
	other := mkProject(t, "```sh\nnpm test\n```\n")
	sha := "0123456789abcdef0123456789abcdef01234567"
	cases := []struct {
		name   string
		mutate func(*Approval)
		plan   *planner.Plan
		want   string
	}{
		{"stale fingerprint", func(a *Approval) { a.PlanFingerprint = other.Fingerprint }, base, "fingerprint"},
		{"commit mismatch", func(a *Approval) { a.Commit = &sha }, base, "commit"},
		{"host mounts", func(a *Approval) { a.AllowHostMounts = true }, base, "host mounts"},
		{"privileged", func(a *Approval) { a.AllowPrivileged = true }, base, "privileged"},
		{"empty statement", func(a *Approval) { a.Statement = "  " }, base, "statement"},
		{"bad version", func(a *Approval) { a.Version = "2" }, base, "version"},
		{"no network", func(a *Approval) { a.ApprovedNetwork = "" }, base, "network mode"},
		{"network mismatch", func(a *Approval) { a.ApprovedNetwork = "restricted-install" }, base, "does not match attested"},
		{"unacked reason", func(a *Approval) { a.AcknowledgedReasons = nil }, mkNeedsReview(t), "not acknowledged"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ap := approvalFor(tc.plan)
			tc.mutate(ap)
			err := Authorize(validAttestation(), tc.plan, ap)
			if err == nil {
				t.Fatal("expected denial")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q missing %q", err.Error(), tc.want)
			}
		})
	}
}

// mkNeedsReview builds a plan with review reasons (unsupported stack).
func mkNeedsReview(t *testing.T) *planner.Plan {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("[package]\nname=\"x\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := inspector.Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := planner.Build(&rep.Snapshot)
	if !p.NeedsReview {
		t.Fatal("expected a needs-review plan")
	}
	return p
}

func TestDenyAccumulates(t *testing.T) {
	p := mkProject(t, "```sh\nnpm start\n```\n")
	ap := approvalFor(p)
	ap.PlanFingerprint = "stale"
	ap.AllowHostMounts = true
	ap.Statement = ""
	err := Authorize(validAttestation(), p, ap)
	if err == nil {
		t.Fatal("expected denial")
	}
	if len(err.(*DenyError).Reasons) < 3 {
		t.Fatalf("expected accumulated reasons, got %v", err)
	}
}
