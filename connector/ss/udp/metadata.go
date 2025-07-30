package ss

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	key            string
	connectTimeout time.Duration
	udpBufferSize  int
}

func (c *ssuConnector) parseMetadata(md mdata.Metadata) (err error) {
	c.md.key = mdutil.GetString(md, "key")
	c.md.connectTimeout = mdutil.GetDuration(md, "timeout", "connectTimeout")
	c.md.udpBufferSize = mdutil.GetInt(md, "udpBufferSize", "udp.bufferSize")

	return
}
