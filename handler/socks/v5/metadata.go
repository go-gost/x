package v5

import (
	"math"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

type metadata struct {
	readTimeout       time.Duration
	noTLS             bool
	enableBind        bool
	enableUDP         bool
	udpBufferSize     int
	compatibilityMode bool
	hash              string
}

func (h *socks5Handler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		readTimeout       = "readTimeout"
		noTLS             = "notls"
		enableBind        = "bind"
		enableUDP         = "udp"
		udpBufferSize     = "udpBufferSize"
		compatibilityMode = "comp"
		hash              = "hash"
	)

	h.md.readTimeout = mdutil.GetDuration(md, readTimeout)
	h.md.noTLS = mdutil.GetBool(md, noTLS)
	h.md.enableBind = mdutil.GetBool(md, enableBind)
	h.md.enableUDP = mdutil.GetBool(md, enableUDP)

	if bs := mdutil.GetInt(md, udpBufferSize); bs > 0 {
		h.md.udpBufferSize = int(math.Min(math.Max(float64(bs), 512), 64*1024))
	} else {
		h.md.udpBufferSize = 4096
	}

	h.md.compatibilityMode = mdutil.GetBool(md, compatibilityMode)
	h.md.hash = mdutil.GetString(md, hash)

	return nil
}
