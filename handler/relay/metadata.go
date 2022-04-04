package relay

import (
	"math"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	readTimeout   time.Duration
	enableBind    bool
	udpBufferSize int
	noDelay       bool
}

func (h *relayHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		readTimeout   = "readTimeout"
		enableBind    = "bind"
		udpBufferSize = "udpBufferSize"
		noDelay       = "nodelay"
	)

	h.md.readTimeout = mdx.GetDuration(md, readTimeout)
	h.md.enableBind = mdx.GetBool(md, enableBind)
	h.md.noDelay = mdx.GetBool(md, noDelay)

	if bs := mdx.GetInt(md, udpBufferSize); bs > 0 {
		h.md.udpBufferSize = int(math.Min(math.Max(float64(bs), 512), 64*1024))
	} else {
		h.md.udpBufferSize = 1500
	}
	return
}
