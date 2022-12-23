package tun

import (
	"net"
	"strings"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	tun_util "github.com/go-gost/x/internal/util/tun"
)

const (
	defaultMTU            = 1350
	defaultReadBufferSize = 4096
)

type metadata struct {
	config         *tun_util.Config
	readBufferSize int
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

	l.md.readBufferSize = mdutil.GetInt(md, "tun.rbuf", "rbuf", "readBufferSize")
	if l.md.readBufferSize <= 0 {
		l.md.readBufferSize = defaultReadBufferSize
	}

	config := &tun_util.Config{
		Name: mdutil.GetString(md, name),
		Peer: mdutil.GetString(md, peer),
		MTU:  mdutil.GetInt(md, mtu),
	}
	if config.MTU <= 0 {
		config.MTU = defaultMTU
	}
	if gw := mdutil.GetString(md, gateway); gw != "" {
		config.Gateway = net.ParseIP(gw)
	}

	for _, s := range strings.Split(mdutil.GetString(md, netKey), ",") {
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

	for _, s := range strings.Split(mdutil.GetString(md, route), ",") {
		var route tun_util.Route
		_, ipNet, _ := net.ParseCIDR(strings.TrimSpace(s))
		if ipNet == nil {
			continue
		}
		route.Net = *ipNet
		route.Gateway = config.Gateway

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
				route.Gateway = config.Gateway
			}

			config.Routes = append(config.Routes, route)
		}
	}

	l.md.config = config

	return
}
