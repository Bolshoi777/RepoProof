package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func validAttestation() Attestation {
	return Attestation{
		WorkerKind:   "test-vm",
		ImageDigest:  "sha256:" + strings.Repeat("a", 64),
		PolicyDigest: "sha256:" + strings.Repeat("b", 64),
		Network:      NetworkGuestOnly,
		HostMounts:   0,
		Privileged:   false,
		Limits:       DefaultLimits(),
		Attested:     true,
	}
}

func TestGateAllowsValid(t *testing.T) {
	if err := Gate(validAttestation()); err != nil {
		t.Fatalf("valid attestation blocked: %v", err)
	}
}

func TestGateTable(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Attestation)
		want   string
	}{
		{"unattested", func(a *Attestation) { a.Attested = false }, "not attested"},
		{"no backend", func(a *Attestation) { a.WorkerKind = "none" }, "no worker backend"},
		{"empty kind", func(a *Attestation) { a.WorkerKind = "" }, "no worker backend"},
		{"no image", func(a *Attestation) { a.ImageDigest = "" }, "image digest"},
		{"malformed image digest", func(a *Attestation) { a.ImageDigest = "image-1" }, "image digest"},
		{"no policy", func(a *Attestation) { a.PolicyDigest = "" }, "policy digest"},
		{"malformed policy digest", func(a *Attestation) { a.PolicyDigest = "sha256:xyz" }, "policy digest"},
		{"host mount", func(a *Attestation) { a.HostMounts = 1 }, "host mounts"},
		{"privileged", func(a *Attestation) { a.Privileged = true }, "privileged"},
		{"unknown net", func(a *Attestation) { a.Network = NetworkUnknown }, "network mode"},
		{"no limits", func(a *Attestation) { a.Limits = ResourceLimits{} }, "resource limits"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := validAttestation()
			tc.mutate(&a)
			err := Gate(a)
			if err == nil {
				t.Fatal("expected BLOCKED_SECURITY, got nil")
			}
			var berr *BlockError
			if !errors.As(err, &berr) {
				t.Fatalf("expected *BlockError, got %T", err)
			}
			if !strings.Contains(err.Error(), "BLOCKED_SECURITY") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q missing %q", err, tc.want)
			}
		})
	}
}

func TestGateAccumulatesReasons(t *testing.T) {
	a := Attestation{} // everything missing
	err := Gate(a)
	if err == nil {
		t.Fatal("expected refusal")
	}
	if len(err.(*BlockError).Reasons) < 5 {
		t.Fatalf("expected multiple reasons, got %v", err)
	}
}

// TestNullWorkerRefusesEverything is the G2-01 fail-closed proof:
// without a backend, attestation and teardown both refuse with
// ErrNoWorker and perform no work.
func TestNullWorkerRefusesEverything(t *testing.T) {
	var w Executor = NullWorker{}
	if _, err := w.Attest(context.Background()); !errors.Is(err, ErrNoWorker) {
		t.Fatalf("Attest = %v, want ErrNoWorker", err)
	}
	if err := w.Destroy(context.Background(), "run-1"); !errors.Is(err, ErrNoWorker) {
		t.Fatalf("Destroy = %v, want ErrNoWorker", err)
	}
}

func TestDefaultLimitsPositive(t *testing.T) {
	if err := Gate(validAttestation()); err != nil {
		t.Fatal(err)
	}
	l := DefaultLimits()
	if l.CPUCores <= 0 || l.MemoryMB <= 0 || l.DiskMB <= 0 || l.WallSeconds <= 0 || l.MaxOutputBytes <= 0 {
		t.Fatalf("default limits non-positive: %+v", l)
	}
}
