package tap

import (
	"net"
	"strings"

	mdata "github.com/go-gost/core/metadata"
	tap_util "github.com/go-gost/x/internal/util/tap"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	DefaultMTU = 1420
)

type metadata struct {
	config *tap_util.Config
}

func (l *tapListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		name    = "name"
		netKey  = "net"
		mtu     = "mtu"
		route   = "route"
		routes  = "routes"
		gateway = "gw"
	)

	config := &tap_util.Config{
		Name:    mdutil.GetString(md, name),
		Net:     mdutil.GetString(md, netKey),
		MTU:     mdutil.GetInt(md, mtu),
		Gateway: mdutil.GetString(md, gateway),
	}
	if config.MTU <= 0 {
		config.MTU = DefaultMTU
	}

	gw := net.ParseIP(config.Gateway)

	for _, s := range strings.Split(mdutil.GetString(md, route), ",") {
		var route tap_util.Route
		_, ipNet, _ := net.ParseCIDR(strings.TrimSpace(s))
		if ipNet == nil {
			continue
		}
		route.Net = *ipNet
		route.Gateway = gw

		config.Routes = append(config.Routes, route)
	}

	for _, s := range mdutil.GetStrings(md, routes) {
		ss := strings.SplitN(s, " ", 2)
		if len(ss) == 2 {
			var route tap_util.Route
			_, ipNet, _ := net.ParseCIDR(strings.TrimSpace(ss[0]))
			if ipNet == nil {
				continue
			}
			route.Net = *ipNet
			route.Gateway = net.ParseIP(ss[1])
			if route.Gateway == nil {
				route.Gateway = gw
			}

			config.Routes = append(config.Routes, route)
		}
	}

	l.md.config = config

	return
}
