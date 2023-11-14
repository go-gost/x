package relay

import (
	"math"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	"github.com/go-gost/x/internal/util/mux"
)

type metadata struct {
	readTimeout   time.Duration
	enableBind    bool
	udpBufferSize int
	noDelay       bool
	hash          string
	muxCfg        *mux.Config
}

func (h *relayHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		readTimeout   = "readTimeout"
		enableBind    = "bind"
		udpBufferSize = "udpBufferSize"
		noDelay       = "nodelay"
		hash          = "hash"
	)

	h.md.readTimeout = mdutil.GetDuration(md, readTimeout)
	h.md.enableBind = mdutil.GetBool(md, enableBind)
	h.md.noDelay = mdutil.GetBool(md, noDelay)

	if bs := mdutil.GetInt(md, udpBufferSize); bs > 0 {
		h.md.udpBufferSize = int(math.Min(math.Max(float64(bs), 512), 64*1024))
	} else {
		h.md.udpBufferSize = 4096
	}

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

	return
}
