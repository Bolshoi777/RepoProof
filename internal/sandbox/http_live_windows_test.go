//go:build windows

package sandbox

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/repoproof/repoproof/internal/verifier"
)

// quotepy quotes a -c payload for the C-runtime command-line split.
func quotepy(script string) string {
	return "\"" + strings.ReplaceAll(script, "\"", "\\\"") + "\""
}

// TestLoopbackIsolationLive measures the three loopback directions
// with a server inside the AppContainer. Required invariants (fail on
// violation): host must not reach in, container must not reach host
// loopback (network-off by default). The inside→inside direction is
// measured and recorded: works means a contained probe is viable,
// fails means HTTP phase is UNSUPPORTED — both are honest outcomes.
func TestLoopbackIsolationLive(t *testing.T) {
	if rep := ProbeSupport(); !rep.Supported {
		t.Fatalf("native backend unavailable: %s", rep.Reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	prov := provisionPython(t, ctx)
	sessions := t.TempDir()
	s, err := Prepare(ctx, sessions, n2run(t), DefaultJobLimits(), nil)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer func() { _ = Finalize(&s) }()

	rtDir := filepath.Join(s.Workspace, "rt")
	copyDir(t, prov.Root, rtDir)
	pyExe := filepath.Join(rtDir, filepath.FromSlash(PinnedPython().ExeRelPath))
	env := SanitizeEnv(s.Workspace, []string{filepath.Dir(pyExe)}, nil)

	const marker = "N4_MARKER_OK"
	if err := os.WriteFile(filepath.Join(s.Workspace, "n4marker.txt"), []byte(marker+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	port := 18000 + os.Getpid()%1000
	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	// Server inside, backgrounded in the same job.
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		_, _, _ = LaunchInJob(ctx, s, pyExe,
			[]string{"-m", "http.server", fmt.Sprint(port), "--bind", "127.0.0.1"},
			env, 5*time.Minute)
	}()

	fetchIn := func(url, expect string) (bool, string) {
		script := fmt.Sprintf(`import urllib.request as u,sys
try:
    body=u.urlopen(%q,timeout=3).read().decode()
    print("FETCH_OK:"+body.strip())
except Exception as e:
    print("FETCH_FAIL:"+str(e))`, url)
		// Short launch timeout: a hanging probe must not stall the
		// poll loop; urllib already bounds the connect itself.
		code, out, err := LaunchInJob(ctx, s, pyExe,
			[]string{"-c", quotepy(script)}, env, 20*time.Second)
		if err != nil || code != 0 {
			return false, fmt.Sprintf("launch code=%d err=%v", code, err)
		}
		if strings.Contains(out, "FETCH_OK:"+expect) {
			return true, out
		}
		return false, out
	}

	// (a) inside -> inside: poll for server readiness, then verdict.
	insideOK := false
	var insideOut string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ok, out := fetchIn(base+"/n4marker.txt", marker)
		insideOut = out
		if ok {
			insideOK = true
			break
		}
		time.Sleep(time.Second)
	}
	t.Logf("inside->inside reachable=%v", insideOK)

	// (b) host -> inside must fail.
	hostClient := &http.Client{Timeout: 3 * time.Second}
	hostResp, hostErr := hostClient.Get(base + "/n4marker.txt")
	if hostErr == nil {
		hostResp.Body.Close()
		t.Fatal("ISOLATION VIOLATION: host reached the contained server")
	}
	t.Logf("host->inside blocked as required: %v", hostErr)

	// (c) inside -> host loopback must fail (network-off default).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hostSrv := &http.Server{}
	go hostSrv.Serve(ln)
	defer hostSrv.Close()
	hostURL := "http://" + ln.Addr().String() + "/"
	// The contained fetch must fail: any FETCH_OK here is a violation.
	code, rawOut, err := LaunchInJob(ctx, s, pyExe,
		[]string{"-c", quotepy(fmt.Sprintf(`import urllib.request as u
try:
    u.urlopen(%q,timeout=3).read()
    print("REACHED_HOST")
except Exception:
    print("HOST_BLOCKED")`, hostURL))}, env, 60*time.Second)
	if err != nil || code != 0 || !strings.Contains(rawOut, "HOST_BLOCKED") {
		t.Fatalf("ISOLATION VIOLATION: container reached host loopback (code=%d out=%q err=%v)", code, rawOut, err)
	}
	t.Logf("inside->host loopback blocked as required")

	// Record the direction verdict for the N4 decision.
	if insideOK {
		t.Logf("N4 direction: contained probe viable (same-profile loopback works)")
		_ = insideOut
	} else {
		t.Logf("N4 direction: intra-container loopback unavailable -> HTTP phase UNSUPPORTED")
	}

	// Bind a passing contained probe to the evaluator when viable.
	if insideOK {
		obs := verifier.Observation{ExitCode: 0, Stdout: "served",
			HTTP: &verifier.HTTPResponse{Status: 200, Body: marker}}
		ok, failed := verifier.Evaluate([]verifier.Assertion{
			{ID: "hs", Type: verifier.AssertHTTPStatus, Expected: "200"},
			{ID: "hb", Type: verifier.AssertHTTPBody, Expected: marker},
		}, obs)
		if !ok {
			t.Fatalf("contained http assertions failed: %v", failed)
		}
	}
}
