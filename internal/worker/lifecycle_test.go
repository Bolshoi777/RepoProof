package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestRunWithTimeoutFast(t *testing.T) {
	err := RunWithTimeout(context.Background(), "r1", 5, func(ctx context.Context) error {
		return nil
	})
	if err != nil {
		t.Fatalf("fast fn: %v", err)
	}
}

func TestRunWithTimeoutRefusesUnbounded(t *testing.T) {
	called := false
	for _, limit := range []int{0, -1} {
		err := RunWithTimeout(context.Background(), "r", limit, func(ctx context.Context) error {
			called = true
			return nil
		})
		if err == nil {
			t.Fatalf("limit %d must refuse", limit)
		}
	}
	if called {
		t.Fatal("fn must not run with non-positive limit")
	}
}

func TestRunWithTimeoutDeadline(t *testing.T) {
	start := time.Now()
	err := RunWithTimeout(context.Background(), "slow", 1, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	var terr *TimeoutError
	if !errors.As(err, &terr) {
		t.Fatalf("expected *TimeoutError, got %v", err)
	}
	if terr.RunID != "slow" || terr.LimitSeconds != 1 {
		t.Fatalf("timeout identity wrong: %+v", terr)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout took too long: cancellation did not propagate")
	}
}

func TestRunWithTimeoutCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := RunWithTimeout(ctx, "c1", 60, func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	var cerr *CancelledError
	if !errors.As(err, &cerr) {
		t.Fatalf("expected *CancelledError, got %v", err)
	}
}

func TestRunWithTimeoutPropagatesFnError(t *testing.T) {
	sentinel := errors.New("workload failed")
	err := RunWithTimeout(context.Background(), "e1", 60, func(ctx context.Context) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel, got %v", err)
	}
}

func TestCappedWriter(t *testing.T) {
	var buf bytes.Buffer
	c := NewCappedWriter(&buf, 4)
	if _, err := c.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	n, err := c.Write([]byte("cdef"))
	var lerr *LimitError
	if !errors.As(err, &lerr) {
		t.Fatalf("expected *LimitError, got %v", err)
	}
	if n != 2 || buf.String() != "abcd" || c.Kept() != 4 {
		t.Fatalf("n=%d buf=%q kept=%d", n, buf.String(), c.Kept())
	}
	if _, err := c.Write([]byte("x")); !errors.As(err, &lerr) {
		t.Fatalf("further writes must keep failing, got %v", err)
	}
}

func TestCappedWriterZeroLimit(t *testing.T) {
	var buf bytes.Buffer
	c := NewCappedWriter(&buf, 0)
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("zero limit must deny first byte")
	}
}

func regPath(t *testing.T) string {
	t.Helper()
	return t.TempDir() + "/journal.json"
}

func TestRegistryLifecycle(t *testing.T) {
	r, err := OpenRegistry(regPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start("run-1", "vm-1"); err != nil {
		t.Fatal(err)
	}
	if err := r.Start("run-1", "vm-1"); err == nil {
		t.Fatal("duplicate active start must fail")
	}
	if err := r.Heartbeat("run-1"); err != nil {
		t.Fatal(err)
	}
	if err := r.Heartbeat("nope"); !errors.Is(err, ErrUnknownRun) {
		t.Fatalf("unknown heartbeat: %v", err)
	}
	if got := r.Orphans(-time.Second); len(got) != 1 || got[0].ID != "run-1" {
		t.Fatalf("active run must list as orphan past cutoff: %v", got)
	}
	if err := r.Destroy("run-1"); err != nil {
		t.Fatal(err)
	}
	if err := r.Destroy("run-1"); err != nil {
		t.Fatalf("destroy must be idempotent: %v", err)
	}
	if got := r.Orphans(0); len(got) != 0 {
		t.Fatalf("destroyed run is no orphan: %v", got)
	}
	if err := r.Destroy("nope"); !errors.Is(err, ErrUnknownRun) {
		t.Fatalf("unknown destroy: %v", err)
	}
}

// TestRegistryCrashRecovery simulates a controller crash: the journal
// is persisted at Start, so a fresh handle replays the unfinished run
// as an orphan while a heartbeated peer stays alive.
func TestRegistryCrashRecovery(t *testing.T) {
	path := regPath(t)
	r1, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := r1.Start("crashed", "vm-1"); err != nil {
		t.Fatal(err)
	}
	if err := r1.Start("alive", "vm-1"); err != nil {
		t.Fatal(err)
	}
	// Crash: drop r1 without Destroy. Fresh handle replays the file.
	r2, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	// Only the stale one is an orphan with a positive threshold after
	// refreshing the peer heartbeat post-"restart".
	if err := r2.Heartbeat("alive"); err != nil {
		t.Fatal(err)
	}
	// Deterministic check without sleeps: backdate via journal rewrite.
	r2.mu.Lock()
	r2.runs["crashed"].UpdatedUTC = time.Now().UTC().Add(-2 * time.Hour)
	r2.mu.Unlock()
	orphans := r2.Orphans(time.Hour)
	if len(orphans) != 1 || orphans[0].ID != "crashed" {
		t.Fatalf("orphans = %+v", orphans)
	}
	if err := r2.Destroy("crashed"); err != nil {
		t.Fatal(err)
	}
	if err := r2.Destroy("alive"); err != nil {
		t.Fatal(err)
	}
	if got := r2.Orphans(0); len(got) != 0 {
		t.Fatalf("cleanup must clear orphans: %v", got)
	}
}

func TestRegistryCorruptJournal(t *testing.T) {
	path := regPath(t)
	if err := os.WriteFile(path, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRegistry(path); err == nil {
		t.Fatal("corrupt journal must fail loudly, not silently reset")
	}
}
