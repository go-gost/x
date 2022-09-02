package tap

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	tap_util "github.com/go-gost/x/internal/util/tap"
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
		Name:    mdutil.GetString(md, name),
		Net:     mdutil.GetString(md, netKey),
		MTU:     mdutil.GetInt(md, mtu),
		Gateway: mdutil.GetString(md, gateway),
	}
	if config.MTU <= 0 {
		config.MTU = DefaultMTU
	}

	for _, s := range mdutil.GetStrings(md, routes) {
		if s != "" {
			config.Routes = append(config.Routes, s)
		}
	}

	l.md.config = config

	return
}
