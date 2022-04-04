package v4

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	connectTimeout time.Duration
	disable4a      bool
}

func (c *socks4Connector) parseMetadata(md mdata.Metadata) (err error) {
	const (
		connectTimeout = "timeout"
		disable4a      = "disable4a"
	)

	c.md.connectTimeout = mdx.GetDuration(md, connectTimeout)
	c.md.disable4a = mdx.GetBool(md, disable4a)

	return
}
