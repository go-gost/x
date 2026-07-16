package probe

import (
	"testing"
	"time"
)

func TestCmdProber(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		p := &CmdProber{Command: "true"}
		if err := p.Probe(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("failure", func(t *testing.T) {
		p := &CmdProber{Command: "false"}
		if err := p.Probe(); err == nil {
			t.Fatal("expected error for exit 1, got nil")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		p := &CmdProber{
			Command: "sleep 10",
			Timeout: 50 * time.Millisecond,
		}
		start := time.Now()
		err := p.Probe()
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
		if elapsed > 2*time.Second {
			t.Fatalf("timeout took too long: %v", elapsed)
		}
	})

	t.Run("command not found", func(t *testing.T) {
		p := &CmdProber{Command: "nonexistent-command-xyz"}
		if err := p.Probe(); err == nil {
			t.Fatal("expected error for unknown command, got nil")
		}
	})

	t.Run("shell pipeline", func(t *testing.T) {
		p := &CmdProber{Command: "echo hello | grep hello"}
		if err := p.Probe(); err != nil {
			t.Fatalf("shell pipeline failed: %v", err)
		}
	})
}
