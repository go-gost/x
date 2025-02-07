package router

import (
	"fmt"
	"net"

	"github.com/go-gost/core/router"
	"github.com/vishvananda/netlink"
)

func (p *localRouter) setSysRoutes(routes ...*router.Route) error {
	for _, route := range routes {
		if route.Net == nil {
			continue
		}
		gw := net.ParseIP(route.Gateway)
		if gw == nil {
			continue
		}

		p.options.logger.Debugf("ip route replace %s via %s", route.Net, route.Gateway)
		r := netlink.Route{
			Dst: route.Net,
			Gw:  gw,
		}
		if err := netlink.RouteReplace(&r); err != nil {
			return fmt.Errorf("set route %v %v: %v", r.Dst, r.Gw, err)
		}

	}
	return nil
}
