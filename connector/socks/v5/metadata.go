package v5

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	"github.com/go-gost/x/internal/util/mux"
)

const (
	defaultUDPBufferSize = 4096
)

type metadata struct {
	connectTimeout time.Duration
	noTLS          bool
	relay          string
	udpBufferSize  int
	muxCfg         *mux.Config
}

func (c *socks5Connector) parseMetadata(md mdata.Metadata) (err error) {
	const (
		connectTimeout = "timeout"
		noTLS          = "notls"
		relay          = "relay"
		udpBufferSize  = "udpBufferSize"
	)

	c.md.connectTimeout = mdutil.GetDuration(md, connectTimeout)
	c.md.noTLS = mdutil.GetBool(md, noTLS)
	c.md.relay = mdutil.GetString(md, relay)
	c.md.udpBufferSize = mdutil.GetInt(md, udpBufferSize)
	if c.md.udpBufferSize <= 0 {
		c.md.udpBufferSize = defaultUDPBufferSize
	}

	c.md.muxCfg = &mux.Config{
		Version:           mdutil.GetInt(md, "mux.version"),
		KeepAliveInterval: mdutil.GetDuration(md, "mux.keepaliveInterval"),
		KeepAliveDisabled: mdutil.GetBool(md, "mux.keepaliveDisabled"),
		KeepAliveTimeout:  mdutil.GetDuration(md, "mux.keepaliveTimeout"),
		MaxFrameSize:      mdutil.GetInt(md, "mux.maxFrameSize"),
		MaxReceiveBuffer:  mdutil.GetInt(md, "mux.maxReceiveBuffer"),
		MaxStreamBuffer:   mdutil.GetInt(md, "mux.maxStreamBuffer"),
	}
	return
}
