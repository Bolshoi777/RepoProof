package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func fakeRunner(out string, err error) Runner {
	return func(context.Context, string, ...string) (string, error) {
		return out, err
	}
}

func TestProbeLinuxAvailable(t *testing.T) {
	out := `{"ServerVersion":"28.0.0","OSType":"linux","Architecture":"x86_64",` +
		`"OperatingSystem":"Docker Desktop","NCPU":8,"MemTotal":16500000000}`
	p := ProbeDocker(context.Background(), fakeRunner(out, nil))
	if !p.Available {
		t.Fatalf("profile = %+v, want available", p)
	}
	if p.DaemonVersion != "28.0.0" || !p.DesktopHint || p.NCPU != 8 {
		t.Fatalf("fields wrong: %+v", p)
	}
}

func TestProbeWindowsModeBlocked(t *testing.T) {
	win := `{"ServerVersion":"28.0.0","OSType":"windows","Architecture":"x86_64"}`
	p := ProbeDocker(context.Background(), fakeRunner(win, nil))
	if p.Available {
		t.Fatal("windows container mode must not be available")
	}
	if !strings.Contains(p.Reason, ErrWrongMode.Error()) {
		t.Fatalf("reason = %q, want wrong-mode", p.Reason)
	}
}

func TestProbeDaemonDown(t *testing.T) {
	out := "failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine"
	p := ProbeDocker(context.Background(), fakeRunner(out, errors.New("exit status 1")))
	if p.Available {
		t.Fatal("unreachable daemon must not be available")
	}
	if !strings.Contains(p.Reason, ErrDaemonDown.Error()) {
		t.Fatalf("reason = %q, want daemon-down", p.Reason)
	}
}

func TestProbeBinaryAbsent(t *testing.T) {
	p := ProbeDocker(context.Background(), fakeRunner("", errors.New(`exec: "docker": not found`)))
	if p.Available {
		t.Fatal("absent binary must not be available")
	}
	if !strings.Contains(p.Reason, ErrDockerAbsent.Error()) {
		t.Fatalf("reason = %q, want absent", p.Reason)
	}
}

// TestProbeNoDockerOnPATH proves SBX-01's no-engine branch
// deterministically: with docker unresolvable, the real runner reports
// absent without touching any daemon.
func TestProbeNoDockerOnPATH(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	p := ProbeDocker(context.Background(), DefaultRunner)
	if p.Available {
		t.Fatal("profile must be unavailable without docker on PATH")
	}
	if !strings.Contains(p.Reason, ErrDockerAbsent.Error()) {
		t.Fatalf("reason = %q, want absent", p.Reason)
	}
}

// TestProbeLiveDaemon documents this machine's real state without
// asserting on it: CI/dev machines differ, so the test only requires
// that a verdict (available or reasoned-down) is produced.
func TestProbeLiveDaemon(t *testing.T) {
	p := ProbeDocker(context.Background(), DefaultRunner)
	if p.Available && p.OSType != "linux" {
		t.Fatalf("available engine must be linux mode: %+v", p)
	}
	t.Logf("live engine: available=%v reason=%q version=%q", p.Available, p.Reason, p.DaemonVersion)
}

func TestProbeUnparseable(t *testing.T) {
	p := ProbeDocker(context.Background(), fakeRunner("not json {{", nil))
	if p.Available || !strings.Contains(p.Reason, "unparseable") {
		t.Fatalf("profile = %+v", p)
	}
}
