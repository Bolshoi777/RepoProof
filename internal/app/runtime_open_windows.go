//go:build windows

package app

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var runtimeCreateFile = syscall.NewLazyDLL("kernel32.dll").NewProc("CreateFileW")

const (
	runtimeGenericRead   = 0x80000000
	runtimeShareRead     = 0x00000001
	runtimeShareWrite    = 0x00000002
	runtimeShareDelete   = 0x00000004
	runtimeOpenExisting  = 3
	runtimeOpenReparse   = 0x00200000
	runtimeInvalidHandle = ^uintptr(0)
)

// openRuntimeSource prevents a cache junction/symlink from being followed
// after the controller has inspected the runtime tree.
func openRuntimeSource(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, _, callErr := runtimeCreateFile.Call(
		uintptr(unsafe.Pointer(p)), runtimeGenericRead,
		runtimeShareRead|runtimeShareWrite|runtimeShareDelete,
		0, runtimeOpenExisting, runtimeOpenReparse, 0,
	)
	if h == runtimeInvalidHandle {
		return nil, fmt.Errorf("CreateFileW runtime no-follow: %w", callErr)
	}
	f := os.NewFile(h, path)
	if f == nil {
		_ = syscall.CloseHandle(syscall.Handle(h))
		return nil, fmt.Errorf("CreateFileW runtime no-follow: invalid handle")
	}
	return f, nil
}
