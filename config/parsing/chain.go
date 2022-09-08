package parsing

import (
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
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

	c := chain.NewChain(cfg.Name)
	if cfg.Metadata != nil {
		c.WithMetadata(mdx.NewMetadata(cfg.Metadata))
	}

	selector := parseNodeSelector(cfg.Selector)
	for _, hop := range cfg.Hops {
		group := &chain.NodeGroup{}
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

			cr := registry.ConnectorRegistry().Get(v.Connector.Type)(
				connector.AuthOption(parseAuth(v.Connector.Auth)),
				connector.TLSConfigOption(tlsConfig),
				connector.LoggerOption(connectorLogger),
			)

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
			d := registry.DialerRegistry().Get(v.Dialer.Type)(
				dialer.AuthOption(parseAuth(v.Dialer.Auth)),
				dialer.TLSConfigOption(tlsConfig),
				dialer.LoggerOption(dialerLogger),
				dialer.ProxyProtocolOption(ppv),
			)

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

			tr := (&chain.Transport{}).
				WithConnector(cr).
				WithDialer(d).
				WithAddr(v.Addr).
				WithInterface(v.Interface).
				WithSockOpts(sockOpts)

			node := chain.NewNode(v.Name, v.Addr).
				WithTransport(tr).
				WithBypass(bypass.BypassGroup(bypassList(v.Bypass, v.Bypasses...)...)).
				WithResolver(registry.ResolverRegistry().Get(v.Resolver)).
				WithHostMapper(registry.HostsRegistry().Get(v.Hosts)).
				WithMetadata(nm)

			group.AddNode(node)
		}

		sel := selector
		if s := parseNodeSelector(hop.Selector); s != nil {
			sel = s
		}
		if sel == nil {
			sel = defaultNodeSelector()
		}
		group.WithSelector(sel).
			WithBypass(bypass.BypassGroup(bypassList(hop.Bypass, hop.Bypasses...)...))

		c.AddNodeGroup(group)
	}

	return c, nil
}
