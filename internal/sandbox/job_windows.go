//go:build windows

package sandbox

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// Job Object controls (N2): every sandboxed tree lives in an unnamed
// job with kill-on-close, so closing the handle — including after a
// controller crash — terminates the whole tree. Limits are enforced
// where the SKU supports them; unsupported knobs are reported, and the
// mandatory core (kill-on-close, memory, process count) must apply or
// preparation fails closed.

var (
	procCreateJob    = modKernel32.NewProc("CreateJobObjectW")
	procSetJobInfo   = modKernel32.NewProc("SetInformationJobObject")
	procQueryJob     = modKernel32.NewProc("QueryInformationJobObject")
	procAssignJob    = modKernel32.NewProc("AssignProcessToJobObject")
	procTerminateJob = modKernel32.NewProc("TerminateJobObject")
	procResumeThread = modKernel32.NewProc("ResumeThread")
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectBasicAccountingInfo      = 1

	limitKillOnJobClose       = 0x2000
	limitDieOnUnhandled       = 0x0400
	limitActiveProcess        = 0x0008
	limitJobMemory            = 0x0200
	jobObjectAllAccess        = 0x1F001F
	createSuspended           = 0x00000004
	cpuRateControlInformation = 15
	cpuRateEnable             = 0x1
	cpuRateHardCap            = 0x4
)

// basicLimit mirrors JOBOBJECT_BASIC_LIMIT_INFORMATION in MSDN field
// order. Exact size is proven by the round-trip test (set then query
// back): a layout mismatch fails loudly instead of misapplying limits.
type basicLimit struct {
	perProcessUserTimeLimit uint64
	jobMemoryLimit          uint64
	limitFlags              uint32
	_                       uint32 // pad: working-set sizes need 8-alignment
	minWorkingSetSize       uintptr
	maxWorkingSetSize       uintptr
	activeProcessLimit      uint32
	_                       uint32 // pad: affinity needs 8-alignment
	affinity                uintptr
	priorityClass           uint32
	schedulingClass         uint32
}

// ioCounters mirrors IO_COUNTERS in MSDN field order.
type ioCounters struct {
	readOps    uint64
	writeOps   uint64
	otherOps   uint64
	readBytes  uint64
	writeBytes uint64
	otherBytes uint64
}

// extendedLimit mirrors JOBOBJECT_EXTENDED_LIMIT_INFORMATION:
// basic limits + raw I/O counters + four memory caps.
type extendedLimit struct {
	basic              basicLimit
	io                 ioCounters
	processMemoryLimit uint64
	jobMemoryLimit     uint64
	peakProcessMemory  uint64
	peakJobMemory      uint64
}

// JobHandle owns a job object; closing kills the tree (kill-on-close).
type JobHandle syscall.Handle

// CreateJob creates an unnamed job with the mandatory limits applied.
// CPU rate control is best-effort; applied is reported honestly.
func CreateJob(limits JobLimits) (job JobHandle, cpuApplied bool, err error) {
	h, _, errno := procCreateJob.Call(0, 0)
	if h == 0 {
		return 0, false, fmt.Errorf("CreateJobObjectW failed: %v", errno)
	}
	job = JobHandle(h)
	var info extendedLimit
	info.basic.limitFlags = limitKillOnJobClose | limitDieOnUnhandled |
		limitActiveProcess | limitJobMemory
	info.basic.activeProcessLimit = limits.MaxProcesses
	info.jobMemoryLimit = limits.JobMemoryMB << 20
	r, _, errno := procSetJobInfo.Call(uintptr(h),
		jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if r == 0 {
		procCloseHandle.Call(uintptr(h))
		return 0, false, fmt.Errorf("SetInformationJobObject(limits) failed: %v", errno)
	}
	if limits.CPURatePercent > 0 {
		cpuApplied = setCPURate(h, limits.CPURatePercent)
	}
	return job, cpuApplied, nil
}

func setCPURate(h uintptr, percent uint32) bool {
	if percent < 1 {
		percent = 1
	}
	if percent > 100 {
		percent = 100
	}
	var info [2]uint32 // ControlFlags + CpuRate
	info[0] = cpuRateEnable | cpuRateHardCap
	info[1] = percent * 100
	r, _, _ := procSetJobInfo.Call(h, cpuRateControlInformation,
		uintptr(unsafe.Pointer(&info[0])), unsafe.Sizeof(info))
	return r != 0
}

// Assign puts a suspended process into the job. Call before resume.
func (j JobHandle) Assign(hProcess syscall.Handle) error {
	r, _, errno := procAssignJob.Call(uintptr(j), uintptr(hProcess))
	if r == 0 {
		return fmt.Errorf("AssignProcessToJobObject failed: %v", errno)
	}
	return nil
}

// ActiveProcesses queries the live count (proves the tree is inside).
func (j JobHandle) ActiveProcesses() (uint32, error) {
	var info [48]byte
	var retLen uint32
	r, _, errno := procQueryJob.Call(uintptr(j), jobObjectBasicAccountingInfo,
		uintptr(unsafe.Pointer(&info[0])), uintptr(len(info)), uintptr(unsafe.Pointer(&retLen)))
	if r == 0 {
		return 0, fmt.Errorf("QueryInformationJobObject failed: %v", errno)
	}
	// ActiveProcesses is the 11th DWORD (offset 40) of the accounting struct.
	return *(*uint32)(unsafe.Pointer(&info[40])), nil
}

// WaitEmpty gives terminated descendants a bounded join window before the
// controller closes the job/profile. A timeout is an explicit cleanup error;
// callers must still close the handle to enforce kill-on-close.
func (j JobHandle) WaitEmpty(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		count, err := j.ActiveProcesses()
		if err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("job still has %d active process(es)", count)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Close terminates the whole tree via kill-on-close and releases the handle.
func (j JobHandle) Close() error {
	r, _, errno := procCloseHandle.Call(uintptr(j))
	if r == 0 {
		return fmt.Errorf("CloseHandle(job) failed: %v", errno)
	}
	return nil
}

// Terminate kills every process currently assigned to the job but keeps the
// handle open for Finalize/Close. This is used by resource-budget monitors;
// closing the handle remains the final cleanup action.
func (j JobHandle) Terminate() error {
	r, _, errno := procTerminateJob.Call(uintptr(j), 1)
	if r == 0 {
		return fmt.Errorf("TerminateJobObject failed: %v", errno)
	}
	return nil
}

// ReadLimits queries the applied extended limits back. The round-trip
// (set then read) proves the FFI layout: a mismatch fails loudly here
// instead of silently misapplying limits in the kernel.
func (j JobHandle) ReadLimits() (flags uint32, activeProcs uint32, jobMem uint64, err error) {
	var info extendedLimit
	var retLen uint32
	r, _, errno := procQueryJob.Call(uintptr(j), jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), uintptr(unsafe.Pointer(&retLen)))
	if r == 0 {
		return 0, 0, 0, fmt.Errorf("QueryInformationJobObject(limits) failed: %v", errno)
	}
	return info.basic.limitFlags, info.basic.activeProcessLimit, info.jobMemoryLimit, nil
}

// ResumeThread starts a suspended primary thread.
func ResumeThread(hThread syscall.Handle) error {
	r, _, errno := procResumeThread.Call(uintptr(hThread))
	if r == 0 || int32(r) == -1 {
		return fmt.Errorf("ResumeThread failed: %v", errno)
	}
	return nil
}
