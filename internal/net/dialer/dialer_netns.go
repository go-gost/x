//go:build linux && !android

package dialer

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/vishvananda/netns"
)

// switchNetns enters the named network namespace and returns a cleanup
// function that restores the original namespace. The caller must defer
// the returned function.
func switchNetns(name string) (restore func(), err error) {
	runtime.LockOSThread()

	originNs, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("netns.Get(): %v", err)
	}

	var ns netns.NsHandle
	if strings.HasPrefix(name, "/") {
		ns, err = netns.GetFromPath(name)
	} else {
		ns, err = netns.GetFromName(name)
	}
	if err != nil {
		netns.Set(originNs)
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("netns.Get(%s): %v", name, err)
	}

	if err := netns.Set(ns); err != nil {
		ns.Close()
		netns.Set(originNs)
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("netns.Set(%s): %v", name, err)
	}

	return func() {
		netns.Set(originNs)
		ns.Close()
		runtime.UnlockOSThread()
	}, nil
}
