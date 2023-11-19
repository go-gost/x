package tunnel

import (
	"strings"
	"time"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	xingress "github.com/go-gost/x/ingress"
	"github.com/go-gost/x/internal/util/mux"
	"github.com/go-gost/x/registry"
)

const (
	defaultTTL = 15 * time.Second
)

type metadata struct {
	readTimeout             time.Duration
	entryPoint              string
	entryPointID            relay.TunnelID
	entryPointProxyProtocol int
	directTunnel            bool
	tunnelTTL               time.Duration
	ingress                 ingress.Ingress
	sd                      sd.SD
	muxCfg                  *mux.Config
}

func (h *tunnelHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")

	h.md.tunnelTTL = mdutil.GetDuration(md, "tunnel.ttl")
	if h.md.tunnelTTL <= 0 {
		h.md.tunnelTTL = defaultTTL
	}
	h.md.directTunnel = mdutil.GetBool(md, "tunnel.direct")
	h.md.entryPoint = mdutil.GetString(md, "entrypoint")
	h.md.entryPointID = parseTunnelID(mdutil.GetString(md, "entrypoint.id"))
	h.md.entryPointProxyProtocol = mdutil.GetInt(md, "entrypoint.ProxyProtocol")

	h.md.ingress = registry.IngressRegistry().Get(mdutil.GetString(md, "ingress"))
	if h.md.ingress == nil {
		var rules []*ingress.Rule
		for _, s := range strings.Split(mdutil.GetString(md, "tunnel"), ",") {
			ss := strings.SplitN(s, ":", 2)
			if len(ss) != 2 {
				continue
			}
			rules = append(rules, &ingress.Rule{
				Hostname: ss[0],
				Endpoint: ss[1],
			})
		}
		if len(rules) > 0 {
			h.md.ingress = xingress.NewIngress(
				xingress.RulesOption(rules),
				xingress.LoggerOption(logger.Default().WithFields(map[string]any{
					"kind":    "ingress",
					"ingress": "@internal",
				})),
			)
		}
	}
	h.md.sd = registry.SDRegistry().Get(mdutil.GetString(md, "sd"))

	h.md.muxCfg = &mux.Config{
		Version:           mdutil.GetInt(md, "mux.version"),
		KeepAliveInterval: mdutil.GetDuration(md, "mux.keepaliveInterval"),
		KeepAliveDisabled: mdutil.GetBool(md, "mux.keepaliveDisabled"),
		KeepAliveTimeout:  mdutil.GetDuration(md, "mux.keepaliveTimeout"),
		MaxFrameSize:      mdutil.GetInt(md, "mux.maxFrameSize"),
		MaxReceiveBuffer:  mdutil.GetInt(md, "mux.maxReceiveBuffer"),
		MaxStreamBuffer:   mdutil.GetInt(md, "mux.maxStreamBuffer"),
	}
	if h.md.muxCfg.Version == 0 {
		h.md.muxCfg.Version = 2
	}

	return
}
