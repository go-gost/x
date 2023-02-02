package relay

import (
	"math"
	"strings"
	"time"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	xingress "github.com/go-gost/x/ingress"
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

	h.md.entryPoint = mdutil.GetString(md, entryPoint)
	h.md.ingress = registry.IngressRegistry().Get(mdutil.GetString(md, "ingress"))

	if h.md.ingress == nil {
		if ss := strings.Split(mdutil.GetString(md, "tunnel"), ":"); len(ss) == 2 {
			h.md.ingress = xingress.NewIngress(
				xingress.RulesOption([]xingress.Rule{
					{Host: ss[0], Endpoint: ss[1]},
				}),
				xingress.LoggerOption(logger.Default().WithFields(map[string]any{
					"kind": "ingress",
				})),
			)
		}
	}

	return
}
