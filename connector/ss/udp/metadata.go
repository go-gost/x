package ss

import (
	"math"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	key            string
	connectTimeout time.Duration
	bufferSize     int
}

func (c *ssuConnector) parseMetadata(md mdata.Metadata) (err error) {
	const (
		key            = "key"
		connectTimeout = "timeout"
		bufferSize     = "bufferSize" // udp buffer size
	)

	c.md.key = mdx.GetString(md, key)
	c.md.connectTimeout = mdx.GetDuration(md, connectTimeout)

	if bs := mdx.GetInt(md, bufferSize); bs > 0 {
		c.md.bufferSize = int(math.Min(math.Max(float64(bs), 512), 64*1024))
	} else {
		c.md.bufferSize = 1500
	}

	return
}
