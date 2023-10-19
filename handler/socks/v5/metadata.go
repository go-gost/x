package v5

import (
	"math"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	"github.com/go-gost/x/internal/util/mux"
)

type metadata struct {
	readTimeout       time.Duration
	noTLS             bool
	enableBind        bool
	enableUDP         bool
	udpBufferSize     int
	compatibilityMode bool
	hash              string
	muxCfg            *mux.Config
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

	h.md.muxCfg = &mux.Config{
		Version:           mdutil.GetInt(md, "mux.version"),
		KeepAliveInterval: mdutil.GetDuration(md, "mux.keepaliveInterval"),
		KeepAliveDisabled: mdutil.GetBool(md, "mux.keepaliveDisabled"),
		KeepAliveTimeout:  mdutil.GetDuration(md, "mux.keepaliveTimeout"),
		MaxFrameSize:      mdutil.GetInt(md, "mux.maxFrameSize"),
		MaxReceiveBuffer:  mdutil.GetInt(md, "mux.maxReceiveBuffer"),
		MaxStreamBuffer:   mdutil.GetInt(md, "mux.maxStreamBuffer"),
	}

	return nil
}
