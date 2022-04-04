package tap

import (
	mdata "github.com/go-gost/core/metadata"
	tap_util "github.com/go-gost/x/internal/util/tap"
	mdx "github.com/go-gost/x/metadata"
)

const (
	DefaultMTU = 1350
)

type metadata struct {
	config *tap_util.Config
}

func (l *tapListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		name    = "name"
		netKey  = "net"
		mtu     = "mtu"
		routes  = "routes"
		gateway = "gw"
	)

	config := &tap_util.Config{
		Name:    mdx.GetString(md, name),
		Net:     mdx.GetString(md, netKey),
		MTU:     mdx.GetInt(md, mtu),
		Gateway: mdx.GetString(md, gateway),
	}
	if config.MTU <= 0 {
		config.MTU = DefaultMTU
	}

	for _, s := range mdx.GetStrings(md, routes) {
		if s != "" {
			config.Routes = append(config.Routes, s)
		}
	}

	l.md.config = config

	return
}
