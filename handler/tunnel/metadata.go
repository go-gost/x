package tunnel

import (
	"strings"
	"time"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	"github.com/go-gost/relay"
	xingress "github.com/go-gost/x/ingress"
	"github.com/go-gost/x/registry"
)

type metadata struct {
	readTimeout  time.Duration
	noDelay      bool
	hash         string
	directTunnel bool
	entryPointID relay.TunnelID
	ingress      ingress.Ingress
}

func (h *tunnelHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	h.md.noDelay = mdutil.GetBool(md, "nodelay")

	h.md.hash = mdutil.GetString(md, "hash")

	h.md.directTunnel = mdutil.GetBool(md, "tunnel.direct")
	h.md.entryPointID = parseTunnelID(mdutil.GetString(md, "entrypoint.id"))

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

	return
}
