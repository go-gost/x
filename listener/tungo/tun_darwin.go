package tungo

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
)

const (
	defaultTunName = "utun"
	readOffset     = 4
	writeOffset    = 4
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
		peer := l.md.config.Peer
		if peer == "" {
			peer = l.md.config.Net[0].IP.String()
		}
		cmd := fmt.Sprintf("ifconfig %s inet %s %s mtu %d up",
			name, l.md.config.Net[0].String(), peer, l.md.config.MTU)
		l.log.Debug(cmd)

		args := strings.Split(cmd, " ")
		output, er := exec.Command(args[0], args[1:]...).CombinedOutput()
		if len(output) > 0 {
			l.log.Debugf("%s: %s", cmd, string(output))
		}
		if er != nil {
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
		l.log.Debug(cmd)
		args := strings.Split(cmd, " ")
		output, er := exec.Command(args[0], args[1:]...).CombinedOutput()
		if len(output) > 0 {
			l.log.Debugf("%s: %s", cmd, string(output))
		}
		if er != nil {
			return fmt.Errorf("%s: %v", cmd, er)
		}
	}
	return nil
}
