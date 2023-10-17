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
	"github.com/go-gost/x/internal/util/mux"
	"github.com/go-gost/x/registry"
)

type metadata struct {
	readTimeout             time.Duration
	enableBind              bool
	udpBufferSize           int
	noDelay                 bool
	hash                    string
	directTunnel            bool
	entryPoint              string
	entryPointProxyProtocol int
	ingress                 ingress.Ingress
	muxCfg                  *mux.Config
}

func (h *relayHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		readTimeout             = "readTimeout"
		enableBind              = "bind"
		udpBufferSize           = "udpBufferSize"
		noDelay                 = "nodelay"
		hash                    = "hash"
		entryPoint              = "entryPoint"
		entryPointID            = "entryPoint.id"
		entryPointProxyProtocol = "entryPoint.proxyProtocol"
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

	h.md.directTunnel = mdutil.GetBool(md, "tunnel.direct")
	h.md.entryPoint = mdutil.GetString(md, entryPoint)
	h.md.entryPointProxyProtocol = mdutil.GetInt(md, entryPointProxyProtocol)

	h.md.ingress = registry.IngressRegistry().Get(mdutil.GetString(md, "ingress"))
	if h.md.ingress == nil {
		var rules []xingress.Rule
		for _, s := range strings.Split(mdutil.GetString(md, "tunnel"), ",") {
			ss := strings.SplitN(s, ":", 2)
			if len(ss) != 2 {
				continue
			}
			rules = append(rules, xingress.Rule{
				Hostname: ss[0],
				Endpoint: ss[1],
			})
		}
		if len(rules) > 0 {
			h.md.ingress = xingress.NewIngress(
				xingress.RulesOption(rules),
				xingress.LoggerOption(logger.Default().WithFields(map[string]any{
					"kind": "ingress",
				})),
			)
		}
	}

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
