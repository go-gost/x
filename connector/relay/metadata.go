package relay

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	connectTimeout time.Duration
	noDelay        bool
}

func (c *relayConnector) parseMetadata(md mdata.Metadata) (err error) {
	const (
		connectTimeout = "connectTimeout"
		noDelay        = "nodelay"
	)

	c.md.connectTimeout = mdx.GetDuration(md, connectTimeout)
	c.md.noDelay = mdx.GetBool(md, noDelay)

	return
}
