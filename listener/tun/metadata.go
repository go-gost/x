package tun

import (
	"net"
	"strings"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	tun_util "github.com/go-gost/x/internal/util/tun"
)

const (
	DefaultMTU = 1350
)

type metadata struct {
	config *tun_util.Config
}

func (l *tunListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		name    = "name"
		netKey  = "net"
		peer    = "peer"
		mtu     = "mtu"
		route   = "route"
		routes  = "routes"
		gateway = "gw"
	)

	config := &tun_util.Config{
		Name:    mdutil.GetString(md, name),
		Net:     mdutil.GetString(md, netKey),
		Peer:    mdutil.GetString(md, peer),
		MTU:     mdutil.GetInt(md, mtu),
		Gateway: mdutil.GetString(md, gateway),
	}
	if config.MTU <= 0 {
		config.MTU = DefaultMTU
	}

	gw := net.ParseIP(config.Gateway)

	for _, s := range strings.Split(mdutil.GetString(md, route), ",") {
		var route tun_util.Route
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
			var route tun_util.Route
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
