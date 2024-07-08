//go:build !linux

package dialer

func bindDevice(fd uintptr, ifceName string) error {
	return nil
}

func setMark(fd uintptr, mark int) error {
	return nil
}
