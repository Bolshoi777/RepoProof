package app

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/repoproof/repoproof/internal/source"
)

// resolveTarget maps a CLI/GUI target to a local directory the execution
// chain may read (requirements lookup, staging). Local paths pass through
// untouched. GitHub URLs are materialized ONCE into a temp clone (pinned
// HEAD, detached, no hooks, no submodules — see source.Materialize) and
// the caller must run cleanup after the chain finishes. Inspect-only
// paths (inspect/plan/approve) keep using inspector.Inspect, which clones
// and cleans internally per call.
//
// Why this exists (DEBT-020): the chain used to receive the raw target
// string, so any Python run by URL died in autoDeps with exit 20 trying
// to open "<url>/requirements.txt" as a filesystem path. Worse, the
// inspect-clone was already removed by then, so no local path existed at
// all. One materialization per run also keeps the inspected tree and the
// executed tree identical (no TOCTOU between two clones).
func resolveTarget(ctx context.Context, raw string) (local string, cleanup func(), err error) {
	if !strings.HasPrefix(strings.TrimSpace(raw), "https://") {
		return raw, func() {}, nil
	}
	dir, _, cleanup, err := source.Materialize(ctx, raw, "")
	if err != nil {
		return "", nil, err
	}
	return filepath.Join(dir, "repo"), cleanup, nil
}
