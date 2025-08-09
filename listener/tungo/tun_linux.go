package tungo

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"

	"github.com/vishvananda/netlink"
)

const (
	defaultTunName = "tungo"
	readOffset     = 0
	writeOffset    = 16
)

func (l *tunListener) createTun() (dev io.ReadWriteCloser, name string, ip net.IP, err error) {
	if l.md.config.Name == "" {
		l.md.config.Name = defaultTunName
	}
	dev, name, err = l.createTunDevice()
	if err != nil {
		return
	}

	ifce, err := net.InterfaceByName(name)
	if err != nil {
		return
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return
	}

	for _, net := range l.md.config.Net {
		if err = netlink.AddrAdd(link, &netlink.Addr{
			IPNet: &net,
		}); err != nil {
			l.log.Error(err)
			continue
		}
	}
	if len(l.md.config.Net) > 0 {
		ip = l.md.config.Net[0].IP
	}

	if err = netlink.LinkSetUp(link); err != nil {
		return
	}

	if err = l.addRoutes(ifce); err != nil {
		return
	}

	var dnsServers []string
	for _, dns := range l.md.config.DNS {
		dnsServers = append(dnsServers, dns.String())
	}
	if len(dnsServers) > 0 {
		cmd := fmt.Sprintf("resolvectl dns %s %s", name, strings.Join(dnsServers, " "))
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
	}

	return
}

func (l *tunListener) addRoutes(ifce *net.Interface) error {
	for _, route := range l.routes {
		if route.Net == nil {
			continue
		}

		r := netlink.Route{
			Dst: route.Net,
			Gw:  net.ParseIP(route.Gateway),
		}
		if r.Gw == nil {
			r.LinkIndex = ifce.Index
		}
		if err := netlink.RouteReplace(&r); err != nil {
			return fmt.Errorf("add route %v %v: %v", r.Dst, r.Gw, err)
		}
	}
	return nil
}
