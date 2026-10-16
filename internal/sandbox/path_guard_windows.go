//go:build windows

package sandbox

import "os"

func pathHasReparse(info os.FileInfo) bool { return isWindowsReparse(info) }
