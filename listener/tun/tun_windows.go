package tun

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
)

const (
	defaultTunName = "wintun"
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
		ipNet := l.md.config.Net[0]
		cmd := fmt.Sprintf("netsh interface ip set address name=%s "+
			"source=static addr=%s mask=%s gateway=none",
			name, ipNet.IP.String(), ipMask(ipNet.Mask))
		l.logger.Debug(cmd)

		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			err = fmt.Errorf("%s: %v", cmd, er)
			return
		}
		ip = ipNet.IP
	}

	if err = l.addRoutes(name, l.md.config.Gateway); err != nil {
		return
	}

	for _, dns := range l.md.config.DNS {
		cmd := fmt.Sprintf("netsh interface ip add dnsservers name=%s address=%s validate=no", name, dns.String())
		l.logger.Debug(cmd)

		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			err = fmt.Errorf("%s: %v", cmd, er)
			return
		}
	}

	return
}

func (l *tunListener) addRoutes(ifName string, gw net.IP) error {
	for _, route := range l.routes {
		l.deleteRoute(ifName, route.Net.String())

		cmd := fmt.Sprintf("netsh interface ip add route prefix=%s interface=%s store=active",
			route.Net.String(), ifName)
		if gw != nil {
			cmd += " nexthop=" + gw.String()
		}
		l.logger.Debug(cmd)
		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			return fmt.Errorf("%s: %v", cmd, er)
		}
	}
	return nil
}

func (l *tunListener) deleteRoute(ifName string, route string) error {
	cmd := fmt.Sprintf("netsh interface ip delete route prefix=%s interface=%s store=active",
		route, ifName)
	l.logger.Debug(cmd)
	args := strings.Split(cmd, " ")
	return exec.Command(args[0], args[1:]...).Run()
}

func ipMask(mask net.IPMask) string {
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
