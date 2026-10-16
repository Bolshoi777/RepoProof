//go:build !windows

package sandbox

import (
	"context"
	"time"
)

// Stub: the native backend exists on Windows only.
func ProbeSupport() SupportReport {
	return SupportReport{Reason: ErrUnsupported.Error()}
}

func CreateProfile(_, _, _ string) (string, error) { return "", ErrUnsupported }
func DeriveSid(_ string) (string, error)           { return "", ErrUnsupported }
func DeleteProfile(_ string) error                 { return ErrUnsupported }
func GrantWorkspace(_ context.Context, _, _ string) error {
	return ErrUnsupported
}
func LaunchInContainer(_ context.Context, _ string, _ string, _ []string, _ string, _ []string, _ time.Duration) (int, string, error) {
	return 0, "", ErrUnsupported
}
func LaunchInJob(_ context.Context, _ Session, _ string, _ []string, _ []string, _ time.Duration) (int, string, error) {
	return 0, "", ErrUnsupported
}
func Prepare(_ context.Context, _, _ string, _ JobLimits, _ []string) (Session, error) {
	return Session{}, ErrUnsupported
}
func Finalize(_ Session) error { return ErrUnsupported }
func RecoverOrphans(_ string) ([]string, error) {
	return nil, ErrUnsupported
}

func (s *Session) Cancel() error                    { return ErrUnsupported }
func (s *Session) ActiveProcesses() (uint32, error) { return 0, ErrUnsupported }
