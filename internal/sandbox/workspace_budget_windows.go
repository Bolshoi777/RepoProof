//go:build windows

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var errWorkspaceBytesLimit = errors.New("workspace byte limit exceeded")

const workspaceBudgetPoll = 100 * time.Millisecond

const (
	maxWorkspaceEntries = 1_000_000
	maxWorkspaceBytes   = int64(64 << 30)
)

// watchWorkspaceBudget samples the run-owned workspace and asks the caller
// to terminate the root process when the declared budget is exceeded. This
// is deliberately a monitor, not a filesystem quota; reports must disclose
// that distinction.
func watchWorkspaceBudget(ctx context.Context, root string, budgetMB uint64, terminate func(), failures chan<- error, done chan<- struct{}) {
	defer close(done)
	limit := int64(budgetMB) * 1024 * 1024
	ticker := time.NewTicker(workspaceBudgetPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			size, err := workspaceBytesContext(ctx, root, limit)
			if err != nil {
				// The launcher cancels this monitor as soon as the step has
				// finished or timed out. That expected shutdown must not be
				// reported as a scan failure.
				if ctx.Err() != nil {
					return
				}
				if errors.Is(err, errWorkspaceBytesLimit) {
					sendBudgetFailure(failures, fmt.Errorf("%w: %v", ErrWorkspaceBudget, err))
					terminate()
					return
				}
				sendBudgetFailure(failures, fmt.Errorf("%w: %v", ErrWorkspaceScan, err))
				terminate()
				return
			}
			if size > limit {
				sendBudgetFailure(failures, fmt.Errorf("%w: %d bytes > %d bytes", ErrWorkspaceBudget, size, limit))
				terminate()
				return
			}
		}
	}
}

func sendBudgetFailure(ch chan<- error, err error) {
	select {
	case ch <- err:
	default:
	}
}

func workspaceBytes(root string) (int64, error) {
	return workspaceBytesContext(context.Background(), root, maxWorkspaceBytes)
}

func workspaceBytesContext(ctx context.Context, root string, limit int64) (int64, error) {
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return 0, err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return 0, err
	}
	if isWindowsReparse(rootInfo) {
		return 0, fmt.Errorf("workspace root is a reparse point")
	}
	var total int64
	var entries int
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entries >= maxWorkspaceEntries {
			return fmt.Errorf("entry limit exceeded")
		}
		entries++
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				// A running installer may remove a cache/pyc between the
				// directory read and the stat. Deletion cannot increase the
				// measured budget, so skip only this transient case.
				return nil
			}
			return walkErr
		}
		if path == root {
			return nil
		}
		info, ierr := os.Lstat(path)
		if ierr != nil {
			if os.IsNotExist(ierr) {
				return nil
			}
			return ierr
		}
		if isWindowsReparse(info) && entry.Type()&fs.ModeSymlink == 0 {
			return fmt.Errorf("reparse point is not allowed: %s", path)
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			// Never follow a link while measuring an untrusted workspace.
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		canonical, cerr := filepath.EvalSymlinks(path)
		if cerr != nil {
			return cerr
		}
		if !containedPath(canonicalRoot, canonical) {
			return fmt.Errorf("reparse target escapes workspace: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		if info.Size() < 0 || total > limit-info.Size() || total > maxWorkspaceBytes-info.Size() {
			return errWorkspaceBytesLimit
		}
		total += info.Size()
		return nil
	})
	return total, err
}

func isWindowsReparse(info os.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
