package v5

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
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
	udpTimeout     time.Duration
	muxCfg         *mux.Config
}

func (c *socks5Connector) parseMetadata(md mdata.Metadata) (err error) {
	c.md.connectTimeout = mdutil.GetDuration(md, "timeout")
	c.md.noTLS = mdutil.GetBool(md, "notls")
	c.md.relay = mdutil.GetString(md, "relay")
	c.md.udpBufferSize = mdutil.GetInt(md, "udp.bufferSize", "udpBufferSize")
	if c.md.udpBufferSize <= 0 {
		c.md.udpBufferSize = defaultUDPBufferSize
	}
	c.md.udpTimeout = mdutil.GetDuration(md, "udp.timeout")

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
