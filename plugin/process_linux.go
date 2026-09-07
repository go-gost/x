//go:build linux

package plugin

import (
	"os/exec"
	"syscall"
)

// prepare arranges for the child to receive SIGTERM when the parent process
// dies, including an abrupt exit (panic, kill -9). It uses prctl(PR_SET_PDEATHSIG).
func prepare(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGTERM
}

func attach(cmd *exec.Cmd) {}
