//go:build !linux && !windows && !darwin

package tun

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
)

const (
	defaultTunName = "tun0"
)

func (l *tunListener) createTun() (ifce io.ReadWriteCloser, name string, ip net.IP, err error) {
	if l.md.config.Name == "" {
		l.md.config.Name = defaultTunName
	}
	ifce, name, err = l.createTunDevice()
	if err != nil {
		return
	}

	if len(l.md.config.Net) > 0 {
		cmd := fmt.Sprintf("ifconfig %s inet %s mtu %d up",
			name, l.md.config.Net[0].String(), l.md.config.MTU)
		l.logger.Debug(cmd)

		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			err = fmt.Errorf("%s: %v", cmd, er)
			return
		}
		ip = l.md.config.Net[0].IP
	}

	if err = l.addRoutes(name); err != nil {
		return
	}

	return
}

func (l *tunListener) addRoutes(ifName string) error {
	for _, route := range l.routes {
		cmd := fmt.Sprintf("route add -net %s -interface %s", route.Net.String(), ifName)
		l.logger.Debug(cmd)
		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			return fmt.Errorf("%s: %v", cmd, er)
		}
	}
	return nil
}
