package relay

import (
	"math"
	"time"

	"github.com/go-gost/core/ingress"
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	"github.com/go-gost/x/registry"
)

type metadata struct {
	readTimeout   time.Duration
	enableBind    bool
	udpBufferSize int
	noDelay       bool
	hash          string
	entryPoint    string
	ingress       ingress.Ingress
}

func (h *relayHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		readTimeout   = "readTimeout"
		enableBind    = "bind"
		udpBufferSize = "udpBufferSize"
		noDelay       = "nodelay"
		hash          = "hash"
		entryPoint    = "entryPoint"
		ingress       = "ingress"
	)

	h.md.readTimeout = mdutil.GetDuration(md, readTimeout)
	h.md.enableBind = mdutil.GetBool(md, enableBind)
	h.md.noDelay = mdutil.GetBool(md, noDelay)

	if bs := mdutil.GetInt(md, udpBufferSize); bs > 0 {
		h.md.udpBufferSize = int(math.Min(math.Max(float64(bs), 512), 64*1024))
	} else {
		h.md.udpBufferSize = 1500
	}

	h.md.hash = mdutil.GetString(md, hash)

	h.md.entryPoint = mdutil.GetString(md, entryPoint)
	h.md.ingress = registry.IngressRegistry().Get(mdutil.GetString(md, ingress))

	return
}
