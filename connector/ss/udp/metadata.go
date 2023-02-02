package ss

import (
	"math"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
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

	c.md.key = mdutil.GetString(md, key)
	c.md.connectTimeout = mdutil.GetDuration(md, connectTimeout)

	if bs := mdutil.GetInt(md, bufferSize); bs > 0 {
		c.md.bufferSize = int(math.Min(math.Max(float64(bs), 512), 64*1024))
	} else {
		c.md.bufferSize = 4096
	}

	return
}
