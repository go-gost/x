package ss

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	key            string
	connectTimeout time.Duration
	noDelay        bool
}

func (c *ssConnector) parseMetadata(md mdata.Metadata) (err error) {
	const (
		key            = "key"
		connectTimeout = "timeout"
		noDelay        = "nodelay"
	)

	c.md.key = mdx.GetString(md, key)
	c.md.connectTimeout = mdx.GetDuration(md, connectTimeout)
	c.md.noDelay = mdx.GetBool(md, noDelay)

	return
}
