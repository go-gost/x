package tun

import (
	"fmt"
	"io"
	"net"

	"github.com/vishvananda/netlink"

	tun_util "github.com/go-gost/x/internal/util/tun"
)

func (l *tunListener) createTun() (dev io.ReadWriteCloser, name string, ip net.IP, err error) {
	ip, ipNet, err := net.ParseCIDR(l.md.config.Net)
	if err != nil {
		return
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

	if err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		},
	}); err != nil {
		return
	}
	if err = netlink.LinkSetUp(link); err != nil {
		return
	}

	if err = l.addRoutes(ifce, l.md.config.Routes...); err != nil {
		return
	}

	return
}

func (l *tunListener) addRoutes(ifce *net.Interface, routes ...tun_util.Route) error {
	for _, route := range routes {
		r := netlink.Route{
			Dst: &route.Net,
			Gw:  route.Gateway,
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
