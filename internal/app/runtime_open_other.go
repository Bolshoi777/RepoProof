//go:build !windows

package app

import "os"

func openRuntimeSource(path string) (*os.File, error) { return os.Open(path) }
