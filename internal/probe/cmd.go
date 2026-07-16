package probe

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

// CmdProber runs a shell command to determine node health.
// Exit 0 = healthy, non-zero (including timeout) = unhealthy.
type CmdProber struct {
	Command string
	Timeout time.Duration
}

// Probe executes the shell command. Returns nil on exit 0, error otherwise.
func (p *CmdProber) Probe() error {
	ctx := context.Background()
	if p.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.Timeout)
		defer cancel()
	}
	shell, shellFlag := shellCmd()
	args := append([]string{shellFlag}, p.Command)
	cmd := exec.CommandContext(ctx, shell, args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cmd probe: %w", err)
	}
	return nil
}

// shellCmd returns the platform shell and its flag for passing a command string.
func shellCmd() (shell, flag string) {
	if runtime.GOOS == "windows" {
		return "cmd", "/C"
	}
	// ponytail: single-binary "sh" fallback; real Windows nodes need cmd.exe, real
	// Unix nodes have sh. If a platform ships neither, add a build-tag probe file.
	return "sh", "-c"
}
