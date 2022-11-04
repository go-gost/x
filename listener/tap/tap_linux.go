package tap

import (
	"fmt"
	"io"
	"net"

	tap_util "github.com/go-gost/x/internal/util/tap"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func (l *tapListener) createTap() (dev io.ReadWriteCloser, name string, ip net.IP, err error) {
	tap, err := water.New(water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: l.md.config.Name,
		},
	})
	if err != nil {
		return
	}

	dev = tap
	name = tap.Name()

	ifce, err := net.InterfaceByName(name)
	if err != nil {
		return
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return
	}

	if err = netlink.LinkSetMTU(link, l.md.config.MTU); err != nil {
		return
	}

	if l.md.config.Net != "" {
		var ipNet *net.IPNet
		ip, ipNet, err = net.ParseCIDR(l.md.config.Net)
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
	}
	if err = netlink.LinkSetUp(link); err != nil {
		return
	}

	if err = l.addRoutes(ifce, l.md.config.Routes...); err != nil {
		return
	}

	return
}

func (l *tapListener) addRoutes(ifce *net.Interface, routes ...tap_util.Route) error {
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
