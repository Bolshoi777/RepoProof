//go:build windows

package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// Win32 surface used (stdlib LazyDLL only):
// userenv: CreateAppContainerProfileW, DeriveAppContainerSidFromAppContainerName,
// DeleteAppContainerProfile; advapi32: ConvertSidToStringSidW, FreeSid;
// kernel32: CreateProcessW, Initialize/Update/DeleteProcThreadAttributeList,
// WaitForSingleObject, TerminateProcess, GetExitCodeProcess, CloseHandle, LocalFree.

var (
	modUserEnv  = syscall.NewLazyDLL("userenv.dll")
	modAdvapi   = syscall.NewLazyDLL("advapi32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCreateProfile = modUserEnv.NewProc("CreateAppContainerProfile")
	procDeriveSid     = modUserEnv.NewProc("DeriveAppContainerSidFromAppContainerName")
	procDeleteProfile = modUserEnv.NewProc("DeleteAppContainerProfile")
	procSidToString   = modAdvapi.NewProc("ConvertSidToStringSidW")
	procStringToSid   = modAdvapi.NewProc("ConvertStringSidToSidW")
	procFreeSid       = modAdvapi.NewProc("FreeSid")
	procInitAttrList  = modKernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateAttr    = modKernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteAttr    = modKernel32.NewProc("DeleteProcThreadAttributeList")
	procCreateProcess = modKernel32.NewProc("CreateProcessW")
	procWaitSingle    = modKernel32.NewProc("WaitForSingleObject")
	procTerminate     = modKernel32.NewProc("TerminateProcess")
	procGetExitCode   = modKernel32.NewProc("GetExitCodeProcess")
	procCloseHandle   = modKernel32.NewProc("CloseHandle")
	procLocalFree     = modKernel32.NewProc("LocalFree")
	procSetHandleInfo = modKernel32.NewProc("SetHandleInformation")
	procOpenProcToken = modKernel32.NewProc("OpenProcessToken")
	procGetTokenInfo  = modAdvapi.NewProc("GetTokenInformation")
)

const (
	procThreadAttrSecurityCapabilities = 0x20009
	procThreadAttrHandleList           = 0x20002
	handleFlagInherit                  = 0x00000001
	extendedStartupinfoPresent         = 0x00080000
	createUnicodeEnvironment           = 0x00000400
	startfUseStdHandles                = 0x00000100
	waitObject0                        = 0x00000000
	waitTimeout                        = 0x00000102
	tokenQuery                         = 0x00000008
	tokenIsAppContainer                = 29
)

// RequiredProcs lists every native entry point N1 needs. ProbeSupport
// checks presence without mutating the system.
func RequiredProcs() []*syscall.LazyProc {
	return []*syscall.LazyProc{
		procCreateProfile, procDeriveSid, procDeleteProfile, procSidToString, procStringToSid,
		procFreeSid, procInitAttrList, procUpdateAttr, procDeleteAttr,
		procCreateProcess, procWaitSingle, procTerminate, procGetExitCode,
		procCloseHandle, procLocalFree, procOpenProcToken, procGetTokenInfo,
		procTerminateJob,
		procSetHandleInfo,
	}
}

// ProbeSupport reports whether the stable native backend can run here.
// Non-invasive: resolves entry points only, creates nothing.
func ProbeSupport() SupportReport {
	for _, p := range RequiredProcs() {
		if err := p.Find(); err != nil {
			return SupportReport{Reason: "missing win32 entry: " + p.Name}
		}
	}
	return SupportReport{Supported: true}
}

func hresultFailed(hr uintptr) bool { return int32(hr) < 0 }

func hresultErr(op string, hr uintptr) error {
	return fmt.Errorf("%s failed: HRESULT 0x%08X", op, uint32(hr))
}

type securityCapabilities struct {
	appContainerSid uintptr
	capabilities    uintptr
	capabilityCount uint32
	reserved        uint32
}

// sidAndAttributes mirrors SID_AND_ATTRIBUTES for capability entries.
type sidAndAttributes struct {
	sid        uintptr
	attributes uint32
	_          uint32
}

const seGroupEnabled = 0x4

// capabilityPrefix restricts granted capabilities to the AppContainer
// capability range (S-1-15-3-*): well-known lowbox capabilities only.
// Arbitrary SIDs (users, admins) are refused — a capability must never
// become a privilege escalation path.
const capabilityPrefix = "S-1-15-3-"

func stringSidToPSID(s string) (uintptr, error) {
	if !strings.HasPrefix(s, capabilityPrefix) {
		return 0, fmt.Errorf("capability %q outside %q range", s, capabilityPrefix)
	}
	s16, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		return 0, err
	}
	var sid uintptr
	r, _, errno := procStringToSid.Call(uintptr(unsafe.Pointer(s16)), uintptr(unsafe.Pointer(&sid)))
	if r == 0 {
		return 0, fmt.Errorf("ConvertStringSidToSidW(%q) failed: %v", s, errno)
	}
	return sid, nil
}

// startupInfoEx is STARTUPINFO followed by the attribute list pointer.
type startupInfoEx struct {
	si       syscall.StartupInfo
	attrList uintptr
}

type processInformation struct {
	hProcess  syscall.Handle
	hThread   syscall.Handle
	processID uint32
	threadID  uint32
}

// CreateProfile creates a per-run AppContainer profile and returns its
// string SID. Unique names only: an existing name is an error, never
// silently reused.
func CreateProfile(name, display, description string) (string, error) {
	if err := ValidProfileName(name); err != nil {
		return "", err
	}
	n, _ := syscall.UTF16PtrFromString(name)
	d, _ := syscall.UTF16PtrFromString(display)
	desc, _ := syscall.UTF16PtrFromString(description)
	var sid uintptr
	hr, _, _ := procCreateProfile.Call(
		uintptr(unsafe.Pointer(n)),
		uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(desc)),
		0, 0,
		uintptr(unsafe.Pointer(&sid)),
	)
	if hresultFailed(hr) {
		return "", hresultErr("CreateAppContainerProfile", hr)
	}
	defer procFreeSid.Call(sid)
	return sidToString(sid)
}

// DeriveSid returns the string SID of an existing profile.
func DeriveSid(name string) (string, error) {
	if err := ValidProfileName(name); err != nil {
		return "", err
	}
	n, _ := syscall.UTF16PtrFromString(name)
	var sid uintptr
	hr, _, _ := procDeriveSid.Call(
		uintptr(unsafe.Pointer(n)),
		uintptr(unsafe.Pointer(&sid)),
	)
	if hresultFailed(hr) {
		return "", hresultErr("DeriveAppContainerSidFromAppContainerName", hr)
	}
	defer procFreeSid.Call(sid)
	return sidToString(sid)
}

// DeleteProfile removes a per-run profile. Deleting a missing profile
// is an error (proves nothing was silently left behind elsewhere).
func DeleteProfile(name string) error {
	if err := ValidProfileName(name); err != nil {
		return err
	}
	n, _ := syscall.UTF16PtrFromString(name)
	hr, _, _ := procDeleteProfile.Call(uintptr(unsafe.Pointer(n)))
	if hresultFailed(hr) {
		return hresultErr("DeleteAppContainerProfile", hr)
	}
	return nil
}

func sidToString(sid uintptr) (string, error) {
	var strPtr unsafe.Pointer
	ok, _, _ := procSidToString.Call(sid, uintptr(unsafe.Pointer(&strPtr)))
	if ok == 0 || strPtr == nil {
		return "", fmt.Errorf("ConvertSidToStringSidW failed")
	}
	defer procLocalFree.Call(uintptr(strPtr))
	return syscall.UTF16ToString((*[1 << 20]uint16)(strPtr)[:]), nil
}

// IsAppContainerProcess reports the TokenIsAppContainer ground truth
// for a live process handle. whoami display output is not trusted for
// this verdict.
func IsAppContainerProcess(hProcess syscall.Handle) (bool, error) {
	var token syscall.Handle
	r, _, errno := procOpenProcToken.Call(uintptr(hProcess), tokenQuery, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false, fmt.Errorf("OpenProcessToken failed: %v", errno)
	}
	defer procCloseHandle.Call(uintptr(token))
	var isAC uint32
	var retLen uint32
	r, _, errno = procGetTokenInfo.Call(uintptr(token), tokenIsAppContainer,
		uintptr(unsafe.Pointer(&isAC)), unsafe.Sizeof(isAC), uintptr(unsafe.Pointer(&retLen)))
	if r == 0 {
		return false, fmt.Errorf("GetTokenInformation failed: %v", errno)
	}
	return isAC != 0, nil
}

// GrantWorkspace gives the profile SID full control over its workspace
// (OI)(CI) inheritance. icacls is RepoProof's own trusted tooling,
// invoked with fixed shape; workspace and SID are both RepoProof-owned.
func GrantWorkspace(ctx context.Context, workspace, sid string) error {
	args, err := IcaclsGrantArgs(workspace, sid)
	if err != nil {
		return err
	}
	if st, err := os.Stat(workspace); err != nil || !st.IsDir() {
		return fmt.Errorf("workspace is not a directory: %s", workspace)
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls grant failed: %v: %s", err, firstLine(string(out)))
	}
	return nil
}

// ProtectRuntime denies the AppContainer write/delete rights on a staged
// runtime subtree. The workspace remains writable for project files, while
// a setup hook cannot replace the interpreter or its libraries before the
// next launch.
func ProtectRuntime(ctx context.Context, runtimeDir, sid string) error {
	if runtimeDir == "" || !strings.HasPrefix(sid, "S-1-") {
		return fmt.Errorf("runtime path and profile SID are required")
	}
	if st, err := os.Stat(runtimeDir); err != nil || !st.IsDir() {
		return fmt.Errorf("runtime is not a directory: %s", runtimeDir)
	}
	for _, perm := range []string{"W", "D", "DC"} {
		cmd := exec.CommandContext(ctx, "icacls", runtimeDir, "/deny", "*"+sid+":(OI)(CI)"+perm)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("icacls runtime deny %s failed: %v: %s", perm, err, firstLine(string(out)))
		}
	}
	return nil
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' || c == '\r' {
			s = s[:i]
			break
		}
	}
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// LaunchInContainer runs exe (a trusted system binary path chosen by
// the caller, never repository content) inside the named profile's
// AppContainer with zero extra capabilities, stdio captured, and a
// hard wait timeout after which the process is terminated.
// env == nil inherits the parent block (N1 behavior, documented);
// pass SanitizeEnv output to isolate (N2).
func LaunchInContainer(ctx context.Context, profileName, exe string, argv []string, workdir string, env []string, timeout time.Duration) (int, string, error) {
	pi, outR, outW, err := spawnSuspended(profileName, exe, argv, workdir, env, nil)
	if err != nil {
		return 0, "", err
	}
	defer procCloseHandle.Call(uintptr(pi.hProcess))
	defer procCloseHandle.Call(uintptr(pi.hThread))
	outW.Close()
	if err := ResumeThread(pi.hThread); err != nil {
		procTerminate.Call(uintptr(pi.hProcess), 1)
		return 0, "", err
	}
	return waitCollect(ctx, pi.hProcess, outR, timeout, 0, func() {
		procTerminate.Call(uintptr(pi.hProcess), 1)
	})
}

// spawnSuspended creates the contained child suspended. caps lists
// AppContainer capability SIDs (S-1-15-3-*, e.g. internetClient);
// empty means deny-by-default. The caller must resume (directly or
// after job assignment) and close both handles.
func spawnSuspended(profileName, exe string, argv []string, workdir string, env []string, caps []string) (processInformation, *os.File, *os.File, error) {
	var pi processInformation
	if err := ValidProfileName(profileName); err != nil {
		return pi, nil, nil, err
	}
	// Resolve the raw SID for SECURITY_CAPABILITIES.
	n, _ := syscall.UTF16PtrFromString(profileName)
	var sid uintptr
	if hr, _, _ := procDeriveSid.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&sid))); hresultFailed(hr) {
		return pi, nil, nil, hresultErr("DeriveAppContainerSidFromAppContainerName", hr)
	}
	defer procFreeSid.Call(sid)

	// Attribute list with zero capabilities (deny-by-default).
	var attrSize uintptr
	procInitAttrList.Call(0, 2, 0, uintptr(unsafe.Pointer(&attrSize)))
	attrBuf := make([]byte, attrSize)
	attrList := uintptr(unsafe.Pointer(&attrBuf[0]))
	if r, _, _ := procInitAttrList.Call(attrList, 2, 0, uintptr(unsafe.Pointer(&attrSize))); r == 0 {
		return pi, nil, nil, fmt.Errorf("InitializeProcThreadAttributeList failed")
	}
	defer procDeleteAttr.Call(attrList)
	capsArr := make([]sidAndAttributes, 0, len(caps))
	for _, c := range caps {
		psid, err := stringSidToPSID(c)
		if err != nil {
			return pi, nil, nil, err
		}
		defer procLocalFree.Call(psid)
		capsArr = append(capsArr, sidAndAttributes{sid: psid, attributes: seGroupEnabled})
	}
	capsPtr := uintptr(0)
	if len(capsArr) > 0 {
		capsPtr = uintptr(unsafe.Pointer(&capsArr[0]))
	}
	capsVal := securityCapabilities{appContainerSid: sid, capabilities: capsPtr, capabilityCount: uint32(len(capsArr))}
	if r, _, _ := procUpdateAttr.Call(attrList, 0, procThreadAttrSecurityCapabilities,
		uintptr(unsafe.Pointer(&capsVal)), unsafe.Sizeof(capsVal), 0, 0); r == 0 {
		return pi, nil, nil, fmt.Errorf("UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed")
	}

	exe16, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return pi, nil, nil, err
	}
	cmdline := append([]string{exe}, argv...)
	cmdStr, err := syscall.UTF16PtrFromString(strings.Join(cmdline, " "))
	if err != nil {
		return pi, nil, nil, err
	}
	workdir16, err := syscall.UTF16PtrFromString(workdir)
	if err != nil {
		return pi, nil, nil, err
	}
	// Environment block: nil inherits (documented N1 behavior),
	// otherwise the child sees exactly this block. The slice is kept
	// alive in this scope until CreateProcess returns.
	var envPtr uintptr
	var envKeep []uint16
	if env != nil {
		// Manual UTF-16: the block embeds NUL separators, which
		// UTF16FromString rejects. Ends with a double null.
		envKeep = append(utf16.Encode([]rune(strings.Join(env, "\x00")+"\x00")), 0)
		envPtr = uintptr(unsafe.Pointer(&envKeep[0]))
	}

	// Pipes for captured stdio, read asynchronously (no deadlock).
	outR, outW, err := os.Pipe()
	if err != nil {
		return pi, nil, nil, err
	}
	// Only the captured stdout/stderr write end may cross the process
	// boundary. The explicit handle-list attribute prevents unrelated
	// inheritable host handles (sockets, files, credentials) leaking to
	// the untrusted child.
	_, _, _ = procSetHandleInfo.Call(uintptr(outR.Fd()), handleFlagInherit, 0)
	if r, _, errno := procSetHandleInfo.Call(uintptr(outW.Fd()), handleFlagInherit, handleFlagInherit); r == 0 {
		outR.Close()
		outW.Close()
		return pi, nil, nil, fmt.Errorf("SetHandleInformation failed: %v", errno)
	}
	handleList := []uintptr{outW.Fd()}
	if r, _, _ := procUpdateAttr.Call(attrList, 0, procThreadAttrHandleList,
		uintptr(unsafe.Pointer(&handleList[0])), unsafe.Sizeof(handleList[0]), 0, 0); r == 0 {
		outR.Close()
		outW.Close()
		return pi, nil, nil, fmt.Errorf("UpdateProcThreadAttribute(HANDLE_LIST) failed")
	}
	var si startupInfoEx
	// cb covers the whole STARTUPINFOEX, attribute list included.
	si.si.Cb = uint32(unsafe.Sizeof(si))
	si.si.Flags = startfUseStdHandles
	si.si.StdOutput = syscall.Handle(outW.Fd())
	si.si.StdErr = syscall.Handle(outW.Fd())
	si.attrList = attrList

	r, _, errno := procCreateProcess.Call(
		uintptr(unsafe.Pointer(exe16)),
		uintptr(unsafe.Pointer(cmdStr)),
		0, 0, 1,
		extendedStartupinfoPresent|createUnicodeEnvironment|createSuspended,
		envPtr,
		uintptr(unsafe.Pointer(workdir16)),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		outR.Close()
		outW.Close()
		return pi, nil, nil, fmt.Errorf("CreateProcessW failed: %v", errno)
	}

	// Fail closed: a child that is not provably inside the AppContainer
	// must never be treated as sandboxed. Terminate and refuse.
	contained, cerr := IsAppContainerProcess(pi.hProcess)
	if cerr != nil || !contained {
		procTerminate.Call(uintptr(pi.hProcess), 1)
		procWaitSingle.Call(uintptr(pi.hProcess), 5000)
		procCloseHandle.Call(uintptr(pi.hProcess))
		procCloseHandle.Call(uintptr(pi.hThread))
		outR.Close()
		outW.Close()
		return pi, nil, nil, fmt.Errorf("child is not in AppContainer, refused (contained=%v err=%v)", contained, cerr)
	}
	return pi, outR, outW, nil
}

// waitCollect reads stdio until exit, timeout, or cancellation,
// terminating on the latter two. A zero limit selects the bounded
// low-level default; production sessions copy the reviewed contract limit.
func waitCollect(ctx context.Context, hProcess syscall.Handle, outR *os.File, timeout time.Duration, requestedOutputLimit int64, terminate func()) (int, string, error) {
	defer outR.Close()
	var buf bytes.Buffer
	var wg sync.WaitGroup
	const defaultOutputLimit int64 = 64 << 10
	const maxOutputLimit int64 = 64 << 20
	outputLimit := requestedOutputLimit
	if outputLimit <= 0 {
		outputLimit = defaultOutputLimit
	}
	if outputLimit > maxOutputLimit {
		outputLimit = maxOutputLimit
	}
	outputCapped := make(chan struct{}, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		lr := &io.LimitedReader{R: outR, N: outputLimit + 1}
		_, _ = buf.ReadFrom(lr)
		if int64(buf.Len()) > outputLimit {
			buf.Truncate(int(outputLimit))
			select {
			case outputCapped <- struct{}{}:
			default:
			}
			terminate()
		}
	}()

	deadline := time.Now().Add(timeout)
	timedOut := false
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			timedOut = true
			break
		}
		ms := uint32(remaining.Milliseconds())
		if ms > 100 {
			ms = 100
		}
		if ms == 0 {
			ms = 1
		}
		wr, _, _ := procWaitSingle.Call(uintptr(hProcess), uintptr(ms))
		if wr == waitObject0 {
			break
		}
		if wr != waitTimeout {
			break
		}
		if ctx.Err() != nil {
			timedOut = ctx.Err() == context.DeadlineExceeded
			break
		}
	}
	if timedOut || ctx.Err() != nil {
		terminate()
		procWaitSingle.Call(uintptr(hProcess), 5000)
	}
	// Closing our read end unblocks collection even if a descendant kept
	// the inherited write end open after the root process exited.
	_ = outR.Close()
	var exitCode uint32
	procGetExitCode.Call(uintptr(hProcess), uintptr(unsafe.Pointer(&exitCode)))
	wg.Wait()
	out := buf.String()
	select {
	case <-outputCapped:
		return int(exitCode), out, fmt.Errorf("sandboxed process exceeded output limit of %d bytes", outputLimit)
	default:
	}
	if timedOut {
		return int(exitCode), out, fmt.Errorf("sandboxed process timed out")
	}
	return int(exitCode), out, nil
}
