package v5

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

const (
	defaultUDPBufferSize = 4096
)

type metadata struct {
	connectTimeout time.Duration
	noTLS          bool
	relay          string
	udpBufferSize  int
}

func (c *socks5Connector) parseMetadata(md mdata.Metadata) (err error) {
	const (
		connectTimeout = "timeout"
		noTLS          = "notls"
		relay          = "relay"
		udpBufferSize  = "udpBufferSize"
	)

	c.md.connectTimeout = mdx.GetDuration(md, connectTimeout)
	c.md.noTLS = mdx.GetBool(md, noTLS)
	c.md.relay = mdx.GetString(md, relay)
	c.md.udpBufferSize = mdx.GetInt(md, udpBufferSize)
	if c.md.udpBufferSize <= 0 {
		c.md.udpBufferSize = defaultUDPBufferSize
	}

	return
}
