package tap

import (
	mdata "github.com/go-gost/gost/v3/pkg/metadata"
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
		Name:    mdata.GetString(md, name),
		Net:     mdata.GetString(md, netKey),
		MTU:     mdata.GetInt(md, mtu),
		Gateway: mdata.GetString(md, gateway),
	}
	if config.MTU <= 0 {
		config.MTU = DefaultMTU
	}

	for _, s := range mdata.GetStrings(md, routes) {
		if s != "" {
			config.Routes = append(config.Routes, s)
		}
	}

	l.md.config = config

	return
}
