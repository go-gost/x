//go:build android

package dialer

import "fmt"

// switchNetns is a no-op stub — network namespace switching is not supported
// on Android (requires privileged kernel syscalls unavailable to app sandboxes).
func switchNetns(name string) (restore func(), err error) {
	return nil, fmt.Errorf("netns not supported on android")
}
