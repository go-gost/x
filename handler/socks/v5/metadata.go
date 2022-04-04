package v5

import (
	"math"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	readTimeout       time.Duration
	noTLS             bool
	enableBind        bool
	enableUDP         bool
	udpBufferSize     int
	compatibilityMode bool
}

func (h *socks5Handler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		readTimeout       = "readTimeout"
		noTLS             = "notls"
		enableBind        = "bind"
		enableUDP         = "udp"
		udpBufferSize     = "udpBufferSize"
		compatibilityMode = "comp"
	)

	h.md.readTimeout = mdx.GetDuration(md, readTimeout)
	h.md.noTLS = mdx.GetBool(md, noTLS)
	h.md.enableBind = mdx.GetBool(md, enableBind)
	h.md.enableUDP = mdx.GetBool(md, enableUDP)

	if bs := mdx.GetInt(md, udpBufferSize); bs > 0 {
		h.md.udpBufferSize = int(math.Min(math.Max(float64(bs), 512), 64*1024))
	} else {
		h.md.udpBufferSize = 1500
	}

	h.md.compatibilityMode = mdx.GetBool(md, compatibilityMode)

	return nil
}
