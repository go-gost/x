// Package plugin manages the lifecycle of external plugin subprocesses
// spawned from plugin configuration.
//
// Plugins are normally external processes that GOST connects to over HTTP or
// gRPC. When a plugin config carries a non-empty Command, Spawn starts it as a
// child process of GOST so that a single invocation brings up the whole stack,
// and Shutdown terminates it again.
package plugin

import (
	"context"
	"os/exec"
	"strings"
	"sync"
)

var (
	mu       sync.Mutex
	children = map[string]*exec.Cmd{}
	ctx      context.Context
	cancel   context.CancelFunc
)

// Spawn launches command as a child process, deduplicated by its argv string.
// An empty command is a no-op. A previously-started command that is still
// running is reused. It returns an error only when the process fails to start.
func Spawn(command []string) error {
	if len(command) == 0 {
		return nil
	}

	key := strings.Join(command, "\x00")

	mu.Lock()
	if _, ok := children[key]; ok {
		// ponytail: no liveness probe; a crashed child is reaped by the Wait
		// goroutine and respawned on the next reload.
		mu.Unlock()
		return nil
	}

	if ctx == nil {
		ctx, cancel = context.WithCancel(context.Background())
	}

	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	// Stdout/Stderr are left nil so the child's output goes to the null
	// device; the plugin owns its own log storage.
	prepare(cmd)
	if err := cmd.Start(); err != nil {
		mu.Unlock()
		return err
	}
	attach(cmd)

	children[key] = cmd
	mu.Unlock()

	go func(key string, cmd *exec.Cmd) {
		cmd.Wait()
		mu.Lock()
		delete(children, key)
		mu.Unlock()
	}(key, cmd)

	return nil
}

// Shutdown terminates all spawned plugin subprocesses.
func Shutdown() {
	if cancel != nil {
		cancel()
	}
	mu.Lock()
	children = map[string]*exec.Cmd{}
	mu.Unlock()
}
