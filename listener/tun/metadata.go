package tun

import (
	"net"
	"strings"

	mdata "github.com/go-gost/core/metadata"
	tun_util "github.com/go-gost/x/internal/util/tun"
	mdx "github.com/go-gost/x/metadata"
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
		Name:    mdx.GetString(md, name),
		Net:     mdx.GetString(md, netKey),
		Peer:    mdx.GetString(md, peer),
		MTU:     mdx.GetInt(md, mtu),
		Gateway: mdx.GetString(md, gateway),
	}
	if config.MTU <= 0 {
		config.MTU = DefaultMTU
	}

	gw := net.ParseIP(config.Gateway)

	for _, s := range strings.Split(mdx.GetString(md, route), ",") {
		var route tun_util.Route
		_, ipNet, _ := net.ParseCIDR(strings.TrimSpace(s))
		if ipNet == nil {
			continue
		}
		route.Net = *ipNet
		route.Gateway = gw

		config.Routes = append(config.Routes, route)
	}

	for _, s := range mdx.GetStrings(md, routes) {
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
