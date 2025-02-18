package ss

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	key            string
	connectTimeout time.Duration
}

func (c *ssuConnector) parseMetadata(md mdata.Metadata) (err error) {
	const (
		key            = "key"
		connectTimeout = "timeout"
	)

	c.md.key = mdutil.GetString(md, key)
	c.md.connectTimeout = mdutil.GetDuration(md, connectTimeout)

	return
}
