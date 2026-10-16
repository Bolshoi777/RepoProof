//go:build !windows

package inspector

import "os"

func openStageSource(path string) (*os.File, error) { return os.Open(path) }
