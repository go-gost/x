package parsing

import (
	"fmt"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	xchain "github.com/go-gost/x/chain"
	"github.com/go-gost/x/config"
	tls_util "github.com/go-gost/x/internal/util/tls"
	mdx "github.com/go-gost/x/metadata"
	"github.com/go-gost/x/registry"
)

func ParseChain(cfg *config.ChainConfig) (chain.Chainer, error) {
	if cfg == nil {
		return nil, nil
	}

	chainLogger := logger.Default().WithFields(map[string]any{
		"kind":  "chain",
		"chain": cfg.Name,
	})

	c := xchain.NewChain(cfg.Name)
	if cfg.Metadata != nil {
		c.WithMetadata(mdx.NewMetadata(cfg.Metadata))
	}

	sel := parseNodeSelector(cfg.Selector)
	for _, hop := range cfg.Hops {
		var nodes []*chain.Node
		for _, v := range hop.Nodes {
			nodeLogger := chainLogger.WithFields(map[string]any{
				"kind":      "node",
				"connector": v.Connector.Type,
				"dialer":    v.Dialer.Type,
				"hop":       hop.Name,
				"node":      v.Name,
			})
			connectorLogger := nodeLogger.WithFields(map[string]any{
				"kind": "connector",
			})

			tlsCfg := v.Connector.TLS
			if tlsCfg == nil {
				tlsCfg = &config.TLSConfig{}
			}
			tlsConfig, err := tls_util.LoadClientConfig(
				tlsCfg.CertFile, tlsCfg.KeyFile, tlsCfg.CAFile,
				tlsCfg.Secure, tlsCfg.ServerName)
			if err != nil {
				chainLogger.Error(err)
				return nil, err
			}

			var nm metadata.Metadata
			if v.Metadata != nil {
				nm = mdx.NewMetadata(v.Metadata)
			}

			var cr connector.Connector
			if rf := registry.ConnectorRegistry().Get(v.Connector.Type); rf != nil {
				cr = rf(
					connector.AuthOption(parseAuth(v.Connector.Auth)),
					connector.TLSConfigOption(tlsConfig),
					connector.LoggerOption(connectorLogger),
				)
			} else {
				return nil, fmt.Errorf("unregistered connector: %s", v.Connector.Type)
			}

			if v.Connector.Metadata == nil {
				v.Connector.Metadata = make(map[string]any)
			}
			if err := cr.Init(mdx.NewMetadata(v.Connector.Metadata)); err != nil {
				connectorLogger.Error("init: ", err)
				return nil, err
			}

			dialerLogger := nodeLogger.WithFields(map[string]any{
				"kind": "dialer",
			})

			tlsCfg = v.Dialer.TLS
			if tlsCfg == nil {
				tlsCfg = &config.TLSConfig{}
			}
			tlsConfig, err = tls_util.LoadClientConfig(
				tlsCfg.CertFile, tlsCfg.KeyFile, tlsCfg.CAFile,
				tlsCfg.Secure, tlsCfg.ServerName)
			if err != nil {
				chainLogger.Error(err)
				return nil, err
			}

			var ppv int
			if nm != nil {
				ppv = mdutil.GetInt(nm, mdKeyProxyProtocol)
			}

			var d dialer.Dialer
			if rf := registry.DialerRegistry().Get(v.Dialer.Type); rf != nil {
				d = rf(
					dialer.AuthOption(parseAuth(v.Dialer.Auth)),
					dialer.TLSConfigOption(tlsConfig),
					dialer.LoggerOption(dialerLogger),
					dialer.ProxyProtocolOption(ppv),
				)
			} else {
				return nil, fmt.Errorf("unregistered dialer: %s", v.Dialer.Type)
			}

			if v.Dialer.Metadata == nil {
				v.Dialer.Metadata = make(map[string]any)
			}
			if err := d.Init(mdx.NewMetadata(v.Dialer.Metadata)); err != nil {
				dialerLogger.Error("init: ", err)
				return nil, err
			}

			if v.Resolver == "" {
				v.Resolver = hop.Resolver
			}
			if v.Hosts == "" {
				v.Hosts = hop.Hosts
			}
			if v.Interface == "" {
				v.Interface = hop.Interface
			}
			if v.SockOpts == nil {
				v.SockOpts = hop.SockOpts
			}

			var sockOpts *chain.SockOpts
			if v.SockOpts != nil {
				sockOpts = &chain.SockOpts{
					Mark: v.SockOpts.Mark,
				}
			}

			tr := chain.NewTransport(d, cr,
				chain.AddrTransportOption(v.Addr),
				chain.InterfaceTransportOption(v.Interface),
				chain.SockOptsTransportOption(sockOpts),
				chain.TimeoutTransportOption(10*time.Second),
			)

			node := chain.NewNode(v.Name, v.Addr,
				chain.TransportNodeOption(tr),
				chain.BypassNodeOption(bypass.BypassGroup(bypassList(v.Bypass, v.Bypasses...)...)),
				chain.ResoloverNodeOption(registry.ResolverRegistry().Get(v.Resolver)),
				chain.HostMapperNodeOption(registry.HostsRegistry().Get(v.Hosts)),
				chain.MetadataNodeOption(nm),
			)
			nodes = append(nodes, node)
		}

		sl := sel
		if s := parseNodeSelector(hop.Selector); s != nil {
			sl = s
		}
		if sl == nil {
			sl = defaultNodeSelector()
		}

		c.AddHop(xchain.NewChainHop(nodes,
			xchain.SelectorHopOption(sl),
			xchain.BypassHopOption(bypass.BypassGroup(bypassList(hop.Bypass, hop.Bypasses...)...))),
		)
	}

	return c, nil
}
