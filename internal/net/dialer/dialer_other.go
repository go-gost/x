//go:build !linux && !windows && !darwin

package dialer

func bindDevice(network string, fd uintptr, ifceName string) error {
	return nil
}

func setMark(fd uintptr, mark int) error {
	return nil
}
