package tun

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"

	"github.com/go-gost/core/router"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	defaultTunName = "wintun"
	readOffset     = 0
	writeOffset    = 0
)

func init() {
	tun.WintunTunnelType = "GOST"
}

func (l *tunListener) createTun() (ifce io.ReadWriteCloser, name string, ip net.IP, err error) {
	if l.md.config.Name == "" {
		l.md.config.Name = defaultTunName
	}

	if l.md.guid != "" {
		var guid windows.GUID
		guid, err = windows.GUIDFromString(l.md.guid)
		if err != nil {
			return
		}
		tun.WintunStaticRequestedGUID = &guid
	}

	ifce, name, err = l.createTunDevice()
	if err != nil {
		return
	}

	if l.md.config.MTU > 0 {
		cmd := fmt.Sprintf("netsh interface ip set subinterface %s mtu=%d", name, l.md.config.MTU)
		l.log.Debug(cmd)

		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			err = fmt.Errorf("%s: %v", cmd, er)
			return
		}
	}

	if len(l.md.config.Net) > 0 {
		ipNet := l.md.config.Net[0]
		cmd := fmt.Sprintf("netsh interface ip set address name=%s "+
			"source=static addr=%s mask=%s gateway=none",
			name, ipNet.IP.String(), ipMask(ipNet.Mask))
		if ipNet.IP.To4() == nil { // ipv6
			cmd = fmt.Sprintf("netsh interface ipv6 set address %s %s",
				name, ipNet.IP.String())
		}
		l.log.Debug(cmd)

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
		network := "ip"
		if dns.To4() == nil {
			network = "ipv6"
		}
		cmd := fmt.Sprintf("netsh interface %s add dnsservers name=%s address=%s validate=no", network, name, dns.String())
		l.log.Debug(cmd)

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
		l.deleteRoute(ifName, route)

		network := "ip"
		if route.Net.IP.To4() == nil {
			network = "ipv6"
		}
		cmd := fmt.Sprintf("netsh interface %s add route prefix=%s interface=%s store=active",
			network, route.Net.String(), ifName)
		if gw != nil {
			cmd += " nexthop=" + gw.String()
		}
		l.log.Debug(cmd)
		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			return fmt.Errorf("%s: %v", cmd, er)
		}
	}
	return nil
}

func (l *tunListener) deleteRoute(ifName string, route *router.Route) error {
	if ifName == "" || route == nil {
		return nil
	}

	network := "ip"
	if route.Net.IP.To4() == nil {
		network = "ipv6"
	}
	cmd := fmt.Sprintf("netsh interface %s delete route prefix=%s interface=%s store=active",
		network, route.Net.String(), ifName)
	l.log.Debug(cmd)
	args := strings.Split(cmd, " ")
	return exec.Command(args[0], args[1:]...).Run()
}

func ipMask(mask net.IPMask) string {
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
