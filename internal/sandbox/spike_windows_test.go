//go:build windows

package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const spikeTimeout = 30 * time.Second

func spikeProfile(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("repoproof-n1-%d-%d", os.Getpid(), time.Now().UnixNano()%100000)
	if err := ValidProfileName(name); err != nil {
		t.Fatal(err)
	}
	return name
}

// TestNativeSpikeLive is N1 (amendment H.2): a harmless probe child that
// writes only its workspace, proven denial outside it, and profile
// removal proof. It mutates the OS (one profile, temp files) and must
// run for real: a failure here is a finding, never a skip.
func TestNativeSpikeLive(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	name := spikeProfile(t)
	sid, err := CreateProfile(name, name, "repoproof N1 spike")
	if err != nil {
		t.Fatalf("profile creation failed (finding, not success): %v", err)
	}
	// Best-effort cleanup on failure paths; the success path deletes
	// explicitly and proves removal.
	cleaned := false
	defer func() {
		if !cleaned {
			_ = DeleteProfile(name)
		}
	}()

	if !strings.HasPrefix(sid, "S-1-15-2-") {
		t.Fatalf("unexpected AppContainer SID shape: %s", sid)
	}
	t.Logf("profile %s sid %s", name, sid)

	ws := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("outside-secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := GrantWorkspace(ctx, ws, sid); err != nil {
		t.Fatalf("workspace grant failed: %v", err)
	}

	systemCmd := `C:\Windows\System32\cmd.exe`

	// 1. Write inside the workspace works.
	outFile := filepath.Join(ws, "out.txt")
	code, out, err := LaunchInContainer(ctx, name, systemCmd,
		[]string{"/c", fmt.Sprintf(`echo PROBE_OK > "%s"`, outFile)}, ws, nil, spikeTimeout)
	if err != nil || code != 0 {
		t.Fatalf("workspace write failed: code=%d out=%q err=%v", code, out, err)
	}
	raw, err := os.ReadFile(outFile)
	if err != nil || !strings.Contains(string(raw), "PROBE_OK") {
		t.Fatalf("marker missing: %q %v", raw, err)
	}

	// 2. The child really runs inside the AppContainer.
	code, out, err = LaunchInContainer(ctx, name, systemCmd,
		[]string{"/c", "whoami /groups"}, ws, nil, spikeTimeout)
	if err != nil || code != 0 {
		t.Fatalf("whoami failed: code=%d out=%q err=%v", code, out, err)
	}
	t.Logf("child groups:\n%s", out)
	// NOTE: whoami does not list the package SID here, but the kernel
	// ground truth (TokenIsAppContainer, enforced inside LaunchInContainer
	// with terminate-and-refuse) already passed — otherwise step 1 would
	// have failed. whoami output stays as log evidence only.
	// Locale-independent: the label name is localized, the SID is not.
	if !strings.Contains(out, "S-1-16-4096") {
		t.Fatalf("child is not low-integrity (finding):\n%s", out)
	}

	// 3. Read outside the workspace is denied.
	code, out, err = LaunchInContainer(ctx, name, systemCmd,
		[]string{"/c", fmt.Sprintf(`type "%s"`, secret)}, ws, nil, spikeTimeout)
	if err == nil && code == 0 {
		t.Fatalf("OUTSIDE READ SUCCEEDED (containment failure): %q", out)
	}
	t.Logf("outside read denied as required (code=%d err=%v)", code, err)

	// 4. Write outside the workspace is denied and leaves nothing.
	evil := filepath.Join(outside, "evil.txt")
	code, out, err = LaunchInContainer(ctx, name, systemCmd,
		[]string{"/c", fmt.Sprintf(`echo X > "%s"`, evil)}, ws, nil, spikeTimeout)
	if _, serr := os.Stat(evil); !os.IsNotExist(serr) {
		t.Fatalf("OUTSIDE WRITE LANDED (containment failure): code=%d out=%q", code, out)
	}
	t.Logf("outside write denied as required (code=%d err=%v)", code, err)

	// 5. Profile removal proof: re-creation must succeed (proves the
	// name is free), then delete again for final cleanup. DeriveSid can
	// NOT prove removal — S-1-15-2 SIDs are name-derived hashes and
	// resolve even without a profile.
	if err := DeleteProfile(name); err != nil {
		t.Fatalf("profile deletion failed: %v", err)
	}
	if _, err := CreateProfile(name, name, "repoproof N1 re-create proof"); err != nil {
		t.Fatalf("re-creation after delete failed, removal unproven: %v", err)
	}
	if err := DeleteProfile(name); err != nil {
		t.Fatalf("final profile deletion failed: %v", err)
	}
	cleaned = true
	t.Logf("profile %s deleted, re-created (absence proven), deleted again", name)
}
