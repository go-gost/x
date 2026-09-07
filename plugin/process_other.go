//go:build !linux && !windows

package plugin

import "os/exec"

// prepare and attach are no-ops on platforms without a parent-side mechanism
// to terminate the child on parent death. Children spawned here will not
// follow an abrupt parent exit (panic / kill -9).
func prepare(cmd *exec.Cmd) {}

func attach(cmd *exec.Cmd) {}
