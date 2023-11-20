package tun

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
)

const (
	defaultTunName = "utun"
)

func (l *tunListener) createTun() (ifce io.ReadWriteCloser, name string, ip net.IP, err error) {
	if l.md.config.Name == "" {
		l.md.config.Name = defaultTunName
	}
	ifce, name, err = l.createTunDevice()
	if err != nil {
		return
	}

	peer := l.md.config.Peer
	if peer == "" {
		peer = ip.String()
	}
	if len(l.md.config.Net) > 0 {
		cmd := fmt.Sprintf("ifconfig %s inet %s %s mtu %d up",
			name, l.md.config.Net[0].String(), l.md.config.Peer, l.md.config.MTU)
		l.logger.Debug(cmd)
		args := strings.Split(cmd, " ")
		if err = exec.Command(args[0], args[1:]...).Run(); err != nil {
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
		if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
			return err
		}
	}
	return nil
}
