//go:build !windows

package sandbox

import "context"

func watchWorkspaceBudget(context.Context, string, uint64, func(), chan<- error, chan<- struct{}) {}
