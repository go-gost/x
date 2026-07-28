package probe

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/selector"
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

// RunCmdProbe runs a cmd probe and updates the entry marker on success/failure.
// It is shared by chainGroup and hopGroup probe loops to avoid duplicated code.
func RunCmdProbe(cfg *chain.ProbeConfig, marker selector.Marker, log logger.Logger) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if err := (&CmdProber{Command: cfg.Command, Timeout: timeout}).Probe(); err != nil {
		marker.Mark()
		if log != nil {
			log.Debugf("cmd probe failed: %v", err)
		}
	} else {
		marker.Reset()
	}
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
