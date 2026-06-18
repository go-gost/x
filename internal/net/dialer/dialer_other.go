//go:build !unix && !windows

package dialer

func bindDevice(network, address string, fd uintptr, ifceName string) error {
	return nil
}

func setMark(fd uintptr, mark int) error {
	return nil
}

// switchNetns is a no-op stub — network namespace switching is a Linux-only feature.
func switchNetns(name string) (restore func(), err error) {
	return nil, nil
}
