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

	for _, s := range mdutil.GetStrings(md, "routes", "tun.routes") {
		ss := strings.SplitN(s, " ", 2)
		if len(ss) == 2 {
			_, ipNet, _ := net.ParseCIDR(strings.TrimSpace(ss[0]))
			if ipNet == nil {
				continue
			}
			gw := net.ParseIP(ss[1])
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
	}

	for _, v := range strings.Split(mdutil.GetString(md, "dns", "tun.dns"), ",") {
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			config.DNS = append(config.DNS, ip)
		}
	}

	if config.Router == nil && len(l.routes) > 0 {
		config.Router = xrouter.NewRouter(
			xrouter.RoutesOption(l.routes),
			xrouter.LoggerOption(logger.Default().WithFields(map[string]any{
				"kind":   "router",
				"router": "@internal",
			})),
		)
	}

	l.md.config = config

	return
}
