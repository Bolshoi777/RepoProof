//go:build !windows

package sandbox

import "os"

func pathHasReparse(info os.FileInfo) bool { return false }
