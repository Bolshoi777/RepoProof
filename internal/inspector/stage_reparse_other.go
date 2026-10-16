//go:build !windows

package inspector

import "io/fs"

func stageReparse(info fs.FileInfo) bool { return false }
