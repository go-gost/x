package tun

import (
	"net"
	"strings"

	"github.com/go-gost/core/logger"
	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/router"
	tun_util "github.com/go-gost/x/internal/util/tun"
	mdutil "github.com/go-gost/x/metadata/util"
	"github.com/go-gost/x/registry"
	xrouter "github.com/go-gost/x/router"
)

const (
	defaultMTU = 1420
)

type metadata struct {
	config *tun_util.Config
	guid   string
}

func (l *tunListener) parseMetadata(md mdata.Metadata) (err error) {
	config := &tun_util.Config{
		Name:   mdutil.GetString(md, "name", "tun.name"),
		Peer:   mdutil.GetString(md, "peer", "tun.peer"),
		MTU:    mdutil.GetInt(md, "mtu", "tun.mtu"),
		Router: registry.RouterRegistry().Get(mdutil.GetString(md, "router", "tun.router")),
	}
	if config.MTU <= 0 {
		config.MTU = defaultMTU
	}
	if gw := mdutil.GetString(md, "gw", "tun.gw"); gw != "" {
		config.Gateway = net.ParseIP(gw)
	}

	for _, s := range strings.Split(mdutil.GetString(md, "net", "tun.net"), ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		config.Net = append(config.Net, net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		})
	}

	for _, s := range strings.Split(mdutil.GetString(md, "route", "tun.route"), ",") {
		gw := ""
		if config.Gateway != nil {
			gw = config.Gateway.String()
		}
		if route := xrouter.ParseRoute(strings.TrimSpace(s), gw); route != nil {
			l.routes = append(l.routes, route)
		}
	}

	routeStrs := mdutil.GetStrings(md, "routes", "tun.routes")
	if len(routeStrs) == 0 {
		// Fall back to single string (e.g. from URL query parameter routes=0.0.0.0/0)
		if s := mdutil.GetString(md, "routes", "tun.routes"); s != "" {
			routeStrs = strings.Split(s, ",")
		}
	}
	for _, s := range routeStrs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ss := strings.SplitN(s, " ", 2)
		var cidr, gwStr string
		if len(ss) == 2 {
			cidr, gwStr = strings.TrimSpace(ss[0]), ss[1]
		} else {
			cidr = s
		}
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet == nil {
			continue
		}
		gw := net.ParseIP(gwStr)
		if gw == nil {
			gw = config.Gateway
		}

		gateway := ""
		if gw != nil {
			gateway = gw.String()
		}

		l.routes = append(l.routes, &router.Route{
			Net:     ipNet,
			Dst:     ipNet.String(),
			Gateway: gateway,
		})
	}

	for _, v := range strings.Split(mdutil.GetString(md, "dns", "tun.dns"), ",") {
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			config.DNS = append(config.DNS, ip)
		}
	}

	if config.Router == nil && len(l.routes) > 0 {
		config.Router = xrouter.NewRouter(
			xrouter.RoutesOption(l.routes),
			xrouter.NoSysRouteOption(),
			xrouter.LoggerOption(logger.Default().WithFields(map[string]any{
				"kind":   "router",
				"router": "@internal",
			})),
		)
	}

	l.md.config = config

	l.md.guid = mdutil.GetString(md, "guid", "tun.guid")

	return
}
