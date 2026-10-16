//go:build windows

package inspector

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var stageCreateFile = syscall.NewLazyDLL("kernel32.dll").NewProc("CreateFileW")

const (
	stageGenericRead   = 0x80000000
	stageShareRead     = 0x00000001
	stageShareWrite    = 0x00000002
	stageShareDelete   = 0x00000004
	stageOpenExisting  = 3
	stageOpenReparse   = 0x00200000
	stageInvalidHandle = ^uintptr(0)
)

// openStageSource requests FILE_FLAG_OPEN_REPARSE_POINT so a path swapped
// to a junction/symlink between Lstat and read is never transparently
// traversed by the controller.
func openStageSource(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, _, callErr := stageCreateFile.Call(
		uintptr(unsafe.Pointer(p)), stageGenericRead,
		stageShareRead|stageShareWrite|stageShareDelete,
		0, stageOpenExisting, stageOpenReparse, 0,
	)
	if h == stageInvalidHandle {
		return nil, fmt.Errorf("CreateFileW no-follow: %w", callErr)
	}
	f := os.NewFile(h, path)
	if f == nil {
		_ = syscall.CloseHandle(syscall.Handle(h))
		return nil, fmt.Errorf("CreateFileW no-follow: invalid handle")
	}
	return f, nil
}
