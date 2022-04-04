package v5

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	connectTimeout time.Duration
	noTLS          bool
}

func (c *socks5Connector) parseMetadata(md mdata.Metadata) (err error) {
	const (
		connectTimeout = "timeout"
		noTLS          = "notls"
	)

	c.md.connectTimeout = mdx.GetDuration(md, connectTimeout)
	c.md.noTLS = mdx.GetBool(md, noTLS)

	return
}
