// Package worker lifecycle primitives (G2-03, RP-008): timeouts,
// output caps, cancellation and crash-safe run journal. Controller-side
// machinery only: it bounds future backends but executes nothing
// itself. The real VM backend will call these; until then they are
// covered by unit tests against simulated workloads.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// TimeoutError reports a wall-clock overrun. Non-nil handling must
// treat the run outcome as unknown and destroy the worker.
type TimeoutError struct {
	RunID        string
	LimitSeconds int
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("run %s exceeded wall limit of %ds", e.RunID, e.LimitSeconds)
}

// CancelledError reports operator/parent cancellation.
type CancelledError struct {
	RunID string
}

func (e *CancelledError) Error() string {
	return fmt.Sprintf("run %s cancelled", e.RunID)
}

// RunWithTimeout bounds fn by wallSeconds. Non-positive limits refuse
// to run at all (fail closed: no unbounded execution). Deadline
// overruns and parent cancellations map to typed errors; any other
// fn error propagates unwrapped.
func RunWithTimeout(ctx context.Context, runID string, wallSeconds int, fn func(ctx context.Context) error) error {
	if wallSeconds <= 0 {
		return fmt.Errorf("run %s refused: non-positive wall limit", runID)
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(wallSeconds)*time.Second)
	defer cancel()
	err := fn(ctx)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return &TimeoutError{RunID: runID, LimitSeconds: wallSeconds}
	case errors.Is(err, context.Canceled):
		return &CancelledError{RunID: runID}
	default:
		return err
	}
}

// LimitError reports an output cap breach. Kept bytes are retained;
// the rest is dropped and the run must be treated as bounded, not
// complete.
type LimitError struct {
	Limit int64
	Kept  int64
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("output limit exceeded: kept %d of limit %d bytes", e.Kept, e.Limit)
}

// CappedWriter passes through to w until limit bytes are kept, then
// fails every further Write with *LimitError. A non-positive limit
// denies all writes from the first byte.
type CappedWriter struct {
	w     io.Writer
	limit int64
	kept  int64
}

func NewCappedWriter(w io.Writer, limit int64) *CappedWriter {
	return &CappedWriter{w: w, limit: limit}
}

func (c *CappedWriter) Write(p []byte) (int, error) {
	if c.kept >= c.limit {
		return 0, &LimitError{Limit: c.limit, Kept: c.kept}
	}
	room := c.limit - c.kept
	if int64(len(p)) > room {
		n, werr := c.w.Write(p[:room])
		c.kept += int64(n)
		if werr != nil {
			return n, werr
		}
		return n, &LimitError{Limit: c.limit, Kept: c.kept}
	}
	n, err := c.w.Write(p)
	c.kept += int64(n)
	return n, err
}

// Kept returns retained byte count.
func (c *CappedWriter) Kept() int64 { return c.kept }

// RunRecord is one lifecycle journal entry.
type RunRecord struct {
	ID         string    `json:"id"`
	WorkerID   string    `json:"worker_id"`
	StartedUTC time.Time `json:"started_utc"`
	UpdatedUTC time.Time `json:"updated_utc"`
	Destroyed  bool      `json:"destroyed"`
}

// ErrUnknownRun marks operations on runs the journal never saw.
var ErrUnknownRun = errors.New("unknown run id")

// Registry is the crash-safe lifecycle journal. Every mutation is
// persisted atomically, so reopening after a controller crash replays
// unfinished runs as orphans awaiting cleanup. In-memory only until
// OpenRegistry is given a path; tests use t.TempDir paths.
type Registry struct {
	mu   sync.Mutex
	path string
	runs map[string]*RunRecord
}

// OpenRegistry loads the journal at path (missing file = empty journal).
func OpenRegistry(path string) (*Registry, error) {
	r := &Registry{path: path, runs: map[string]*RunRecord{}}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r, nil
		}
		return nil, err
	}
	var recs []RunRecord
	if err := json.Unmarshal(raw, &recs); err != nil {
		return nil, fmt.Errorf("lifecycle journal corrupt: %w", err)
	}
	for i := range recs {
		rec := recs[i]
		r.runs[rec.ID] = &rec
	}
	return r, nil
}

func (r *Registry) persistLocked() error {
	recs := make([]RunRecord, 0, len(r.runs))
	for _, rec := range r.runs {
		recs = append(recs, *rec)
	}
	raw, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

// Start records a new active run. Duplicate active IDs are rejected.
func (r *Registry) Start(id, workerID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec, ok := r.runs[id]; ok && !rec.Destroyed {
		return fmt.Errorf("run %s already active", id)
	}
	now := time.Now().UTC()
	r.runs[id] = &RunRecord{ID: id, WorkerID: workerID, StartedUTC: now, UpdatedUTC: now}
	return r.persistLocked()
}

// Heartbeat marks a run alive. Unknown or destroyed IDs are rejected.
func (r *Registry) Heartbeat(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.runs[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownRun, id)
	}
	if rec.Destroyed {
		return fmt.Errorf("run %s already destroyed", id)
	}
	rec.UpdatedUTC = time.Now().UTC()
	return r.persistLocked()
}

// Destroy marks a run torn down. Idempotent for destroyed runs;
// unknown IDs are an error (nothing to clean).
func (r *Registry) Destroy(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.runs[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownRun, id)
	}
	if rec.Destroyed {
		return nil
	}
	rec.Destroyed = true
	rec.UpdatedUTC = time.Now().UTC()
	return r.persistLocked()
}

// Orphans lists runs that were never destroyed and whose last
// heartbeat is older than staleAfter: candidates for forced cleanup
// after a crash or a lost worker.
func (r *Registry) Orphans(staleAfter time.Duration) []RunRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().UTC().Add(-staleAfter)
	out := []RunRecord{}
	for _, rec := range r.runs {
		if !rec.Destroyed && rec.UpdatedUTC.Before(cutoff) {
			out = append(out, *rec)
		}
	}
	return out
}
