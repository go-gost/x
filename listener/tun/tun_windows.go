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

	// Loop over every configured address so dual-stack (IPv4+IPv6) setups
	// install both addresses, selecting the netsh context by family: "ip"
	// for IPv4, "ipv6" for IPv6. A failing address is logged and skipped so
	// one bad entry doesn't prevent the rest from being applied; the first
	// successfully installed address is reported as the interface IP.
	//
	// Caveat: unlike Linux's netlink.AddrAdd, "netsh interface ip set
	// address" replaces rather than adds, so only a single IPv4 address is
	// supported (one IPv4 + one IPv6 works; multiple IPv4 addresses
	// silently overwrite).
	for _, ipNet := range l.md.config.Net {
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
			l.log.Errorf("%s: %v", cmd, er)
			continue
		}
		if ip == nil {
			ip = ipNet.IP
		}
	}

	// If not a single address could be configured, surface an error rather
	// than returning a nil IP (and thus a nil peer address) to the caller.
	if ip == nil && len(l.md.config.Net) > 0 {
		err = fmt.Errorf("failed to configure any address on interface %s", name)
		return
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
