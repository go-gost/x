//go:build windows

package plugin

import (
	"os/exec"
	"sync"
	"unsafe"

	"github.com/go-gost/core/logger"
	"golang.org/x/sys/windows"
)

var (
	jobOnce sync.Once
	job     windows.Handle
	jobErr  error
)

func initJob() {
	handle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		jobErr = err
		logger.Default().Errorf("plugin: create job object: %v", err)
		return
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(
		handle,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		jobErr = err
		windows.CloseHandle(handle)
		logger.Default().Errorf("plugin: configure job object: %v", err)
		return
	}
	job = handle
}

// processAllAccess is PROCESS_ALL_ACCESS, needed to open the child for
// AssignProcessToJobObject.
const processAllAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xffff

func prepare(cmd *exec.Cmd) {}

// attach assigns the started child to the shared job object whose
// KILL_ON_JOB_CLOSE flag makes the OS terminate the child when the parent
// process dies (even abruptly). Failure (e.g. the parent is already in a job)
// is non-fatal: the child simply loses the die-with-parent guarantee.
func attach(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}

	jobOnce.Do(initJob)
	if jobErr != nil {
		return
	}

	handle, err := windows.OpenProcess(processAllAccess, false, uint32(cmd.Process.Pid))
	if err != nil {
		logger.Default().Errorf("plugin: open child process: %v", err)
		return
	}
	defer windows.CloseHandle(handle)

	if err := windows.AssignProcessToJobObject(job, handle); err != nil {
		logger.Default().Errorf("plugin: assign child to job object: %v", err)
	}
}
