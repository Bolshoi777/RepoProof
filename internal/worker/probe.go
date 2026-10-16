// Container runtime probe (RP-SBX-CHANGE-001 P1): detect a usable
// local Docker engine in Linux-container mode without running any
// repository code. Only fixed-argument `docker info` is invoked;
// no untrusted parameter ever reaches the process call.
//
// Outcomes: engine absent or daemon down -> BLOCKED_ENVIRONMENT;
// wrong container mode -> BLOCKED_SECURITY (SBX-18); usable engine ->
// execution may proceed to attestation (P2+).
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ProbeTimeout bounds the whole engine interrogation.
const ProbeTimeout = 15 * time.Second

// Probe failure causes. Absent/daemon-down mean the environment
// cannot run containers; wrong-mode means the engine cannot run them
// safely for RepoProof's purposes.
var (
	ErrDockerAbsent = errors.New("docker CLI not found")
	ErrDaemonDown   = errors.New("docker daemon unreachable")
	ErrWrongMode    = errors.New("engine is not in Linux container mode")
)

// EngineProfile is the observed runtime capability. Available is true
// only when a Linux-container daemon answered the probe.
type EngineProfile struct {
	Available     bool   `json:"available"`
	DaemonVersion string `json:"daemon_version,omitempty"`
	OSType        string `json:"os_type,omitempty"`
	Architecture  string `json:"architecture,omitempty"`
	DesktopHint   bool   `json:"desktop_hint"`
	NCPU          int    `json:"ncpu,omitempty"`
	MemTotalBytes int64  `json:"mem_total_bytes,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// Runner executes a fixed program. Exposed for deterministic tests;
// production uses DefaultRunner. Implementations must not append
// untrusted arguments.
type Runner func(ctx context.Context, name string, args ...string) (string, error)

// DefaultRunner resolves the binary via PATH (no hardcoded host paths)
// and enforces the caller context deadline.
func DefaultRunner(ctx context.Context, name string, args ...string) (string, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", fmt.Errorf("%w: %s", ErrDockerAbsent, name)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

type dockerInfo struct {
	ServerVersion   string `json:"ServerVersion"`
	OSType          string `json:"OSType"`
	Architecture    string `json:"Architecture"`
	OperatingSystem string `json:"OperatingSystem"`
	NCPU            int    `json:"NCPU"`
	MemTotal        int64  `json:"MemTotal"`
}

// ProbeDocker interrogates the local engine. It never starts
// containers, pulls images, or mounts anything.
func ProbeDocker(ctx context.Context, run Runner) EngineProfile {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	out, err := run(ctx, "docker", "info", "--format", "{{json .}}")
	if err != nil {
		return downProfile(out, err)
	}
	var info dockerInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return EngineProfile{Reason: "docker info output unparseable: " + firstLine(out)}
	}
	if !strings.EqualFold(info.OSType, "linux") {
		return EngineProfile{OSType: info.OSType, Reason: ErrWrongMode.Error() + ": os_type=" + info.OSType}
	}
	return EngineProfile{
		Available:     true,
		DaemonVersion: info.ServerVersion,
		OSType:        info.OSType,
		Architecture:  info.Architecture,
		DesktopHint:   strings.Contains(strings.ToLower(info.OperatingSystem), "docker desktop"),
		NCPU:          info.NCPU,
		MemTotalBytes: info.MemTotal,
	}
}

func downProfile(out string, err error) EngineProfile {
	lower := strings.ToLower(out + " " + err.Error())
	switch {
	case errors.Is(err, ErrDockerAbsent) || strings.Contains(lower, "not found") ||
		strings.Contains(lower, "not recognized") || strings.Contains(lower, "no such file"):
		return EngineProfile{Reason: ErrDockerAbsent.Error()}
	case strings.Contains(lower, "cannot connect") || strings.Contains(lower, "pipe") ||
		strings.Contains(lower, "socket") || strings.Contains(lower, "daemon") ||
		strings.Contains(lower, "refused") || strings.Contains(lower, "timeout") ||
		strings.Contains(lower, "deadline exceeded"):
		detail := firstLine(out)
		if strings.HasPrefix(strings.TrimSpace(out), "{") {
			detail = "daemon error output is machine-readable JSON, see daemon logs"
		}
		return EngineProfile{Reason: ErrDaemonDown.Error() + ": " + detail}
	default:
		return EngineProfile{Reason: "docker probe failed: " + firstLine(out)}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	if s == "" {
		return "(no output)"
	}
	return s
}
