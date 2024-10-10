package sni

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	host           string
	connectTimeout time.Duration
}

func (c *sniConnector) parseMetadata(md mdata.Metadata) (err error) {
	const (
		host           = "host"
		connectTimeout = "timeout"
	)

	c.md.host = mdutil.GetString(md, host)
	c.md.connectTimeout = mdutil.GetDuration(md, connectTimeout)

	return
}
