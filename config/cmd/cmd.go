package cmd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/x/config"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/limiter/conn"
	"github.com/go-gost/x/limiter/traffic"
	mdx "github.com/go-gost/x/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
	"github.com/go-gost/x/registry"
)

var (
	ErrInvalidCmd  = errors.New("invalid cmd")
	ErrInvalidNode = errors.New("invalid node")
)

func BuildConfigFromCmd(serviceList, nodeList []string) (*config.Config, error) {
	namePrefix := ""
	cfg := &config.Config{}

	var chain *config.ChainConfig
	if len(nodeList) > 0 {
		chain = &config.ChainConfig{
			Name: fmt.Sprintf("%schain-0", namePrefix),
		}
		cfg.Chains = append(cfg.Chains, chain)
	}

	for i, node := range nodeList {
		url, err := Norm(node)
		if err != nil {
			return nil, err
		}

		m := map[string]any{}
		for k, v := range url.Query() {
			if len(v) > 0 {
				m[k] = v[0]
			}
		}
		md := mdx.NewMetadata(m)

		hopConfig := &config.HopConfig{
			Name:     fmt.Sprintf("%shop-%d", namePrefix, i),
			Selector: parseSelector(m),
		}

		if v := mdutil.GetString(md, "bypass"); v != "" {
			bypassCfg := &config.BypassConfig{
				Name: fmt.Sprintf("%sbypass-%d", namePrefix, len(cfg.Bypasses)),
			}
			if v[0] == '~' {
				bypassCfg.Whitelist = true
				v = v[1:]
			}
			for _, s := range strings.Split(v, ",") {
				if s == "" {
					continue
				}
				bypassCfg.Matchers = append(bypassCfg.Matchers, s)
			}
			hopConfig.Bypass = bypassCfg.Name
			cfg.Bypasses = append(cfg.Bypasses, bypassCfg)
			delete(m, "bypass")
		}
		if v := mdutil.GetString(md, "resolver"); v != "" {
			resolverCfg := &config.ResolverConfig{
				Name: fmt.Sprintf("%sresolver-%d", namePrefix, len(cfg.Resolvers)),
			}
			for _, rs := range strings.Split(v, ",") {
				if rs == "" {
					continue
				}
				resolverCfg.Nameservers = append(
					resolverCfg.Nameservers,
					&config.NameserverConfig{
						Addr: rs,
					},
				)
			}
			hopConfig.Resolver = resolverCfg.Name
			cfg.Resolvers = append(cfg.Resolvers, resolverCfg)
			delete(m, "resolver")
		}
		if v := mdutil.GetString(md, "hosts"); v != "" {
			hostsCfg := &config.HostsConfig{
				Name: fmt.Sprintf("%shosts-%d", namePrefix, len(cfg.Hosts)),
			}
			for _, s := range strings.Split(v, ",") {
				ss := strings.SplitN(s, ":", 2)
				if len(ss) != 2 {
					continue
				}
				hostsCfg.Mappings = append(
					hostsCfg.Mappings,
					&config.HostMappingConfig{
						Hostname: ss[0],
						IP:       ss[1],
					},
				)
			}
			hopConfig.Hosts = hostsCfg.Name
			cfg.Hosts = append(cfg.Hosts, hostsCfg)
			delete(m, "hosts")
		}

		if v := mdutil.GetString(md, "interface"); v != "" {
			hopConfig.Interface = v
			delete(m, "interface")
		}
		if v := mdutil.GetInt(md, "so_mark"); v > 0 {
			hopConfig.SockOpts = &config.SockOptsConfig{
				Mark: v,
			}
			delete(m, "so_mark")
		}

		nodeConfig, err := buildNodeConfig(url, m)
		if err != nil {
			return nil, err
		}
		nodeConfig.Name = fmt.Sprintf("%snode-0", namePrefix)

		var nodes []*config.NodeConfig
		for _, host := range strings.Split(nodeConfig.Addr, ",") {
			if host == "" {
				continue
			}
			nodeCfg := &config.NodeConfig{}
			*nodeCfg = *nodeConfig
			nodeCfg.Name = fmt.Sprintf("%snode-%d", namePrefix, len(nodes))
			nodeCfg.Addr = host
			nodes = append(nodes, nodeCfg)
		}
		hopConfig.Nodes = nodes

		hopMd := map[string]any{}
		for k, v := range m {
			if strings.HasPrefix(k, "node.") ||
				strings.HasPrefix(k, "connector.") ||
				strings.HasPrefix(k, "dialer.") {
				continue
			}
			if s, found := strings.CutPrefix(k, "hop."); found {
				hopMd[s] = v
				continue
			}

			hopMd[k] = v
		}
		hopConfig.Metadata = hopMd

		chain.Hops = append(chain.Hops, hopConfig)
	}

	var services []*config.ServiceConfig
	for _, svc := range serviceList {
		svc = strings.TrimSpace(svc)
		if svc == "" {
			continue
		}

		if svc[0] == ':' || !strings.Contains(svc, "://") {
			svc = "auto://" + svc
		}

		host, svc := cutHost(svc)

		url, err := Norm(svc)
		if err != nil {
			return nil, err
		}
		url.Host = host

		svcs, err := buildServiceConfig(url)
		if err != nil {
			return nil, err
		}
		services = append(services, svcs...)
	}

	for i, service := range services {
		service.Name = fmt.Sprintf("%sservice-%d", namePrefix, i)
		if chain != nil {
			if service.Listener.Type == "rtcp" || service.Listener.Type == "rudp" {
				service.Listener.Chain = chain.Name
			} else {
				service.Handler.Chain = chain.Name
			}
		}
		cfg.Services = append(cfg.Services, service)

		mh := service.Handler.Metadata
		md := mdx.NewMetadata(mh)
		if v := mdutil.GetInt(md, "retries"); v > 0 {
			service.Handler.Retries = v
			delete(mh, "retries")
		}
		if v := mdutil.GetString(md, "admission"); v != "" {
			admCfg := &config.AdmissionConfig{
				Name: fmt.Sprintf("%sadmission-%d", namePrefix, len(cfg.Admissions)),
			}
			if v[0] == '~' {
				admCfg.Whitelist = true
				v = v[1:]
			}
			for _, s := range strings.Split(v, ",") {
				if s == "" {
					continue
				}
				admCfg.Matchers = append(admCfg.Matchers, s)
			}
			service.Admission = admCfg.Name
			cfg.Admissions = append(cfg.Admissions, admCfg)
			delete(mh, "admission")
		}
		if v := mdutil.GetString(md, "bypass"); v != "" {
			bypassCfg := &config.BypassConfig{
				Name: fmt.Sprintf("%sbypass-%d", namePrefix, len(cfg.Bypasses)),
			}
			if v[0] == '~' {
				bypassCfg.Whitelist = true
				v = v[1:]
			}
			for _, s := range strings.Split(v, ",") {
				if s == "" {
					continue
				}
				bypassCfg.Matchers = append(bypassCfg.Matchers, s)
			}
			service.Bypass = bypassCfg.Name
			cfg.Bypasses = append(cfg.Bypasses, bypassCfg)
			delete(mh, "bypass")
		}
		if v := mdutil.GetString(md, "resolver"); v != "" {
			resolverCfg := &config.ResolverConfig{
				Name: fmt.Sprintf("%sresolver-%d", namePrefix, len(cfg.Resolvers)),
			}
			for _, rs := range strings.Split(v, ",") {
				if rs == "" {
					continue
				}
				resolverCfg.Nameservers = append(
					resolverCfg.Nameservers,
					&config.NameserverConfig{
						Addr:   rs,
						Prefer: mdutil.GetString(md, "prefer"),
					},
				)
			}
			service.Resolver = resolverCfg.Name
			cfg.Resolvers = append(cfg.Resolvers, resolverCfg)
			delete(mh, "resolver")
		}
		if v := mdutil.GetString(md, "hosts"); v != "" {
			hostsCfg := &config.HostsConfig{
				Name: fmt.Sprintf("%shosts-%d", namePrefix, len(cfg.Hosts)),
			}
			for _, s := range strings.Split(v, ",") {
				ss := strings.SplitN(s, ":", 2)
				if len(ss) != 2 {
					continue
				}
				hostsCfg.Mappings = append(
					hostsCfg.Mappings,
					&config.HostMappingConfig{
						Hostname: ss[0],
						IP:       ss[1],
					},
				)
			}
			service.Hosts = hostsCfg.Name
			cfg.Hosts = append(cfg.Hosts, hostsCfg)
			delete(mh, "hosts")
		}

		in := mdutil.GetString(md, "limiter.in")
		out := mdutil.GetString(md, "limiter.out")
		cin := mdutil.GetString(md, "limiter.conn.in")
		cout := mdutil.GetString(md, "limiter.conn.out")
		if in != "" || cin != "" || out != "" || cout != "" {
			limiter := &config.LimiterConfig{
				Name: fmt.Sprintf("%slimiter-%d", namePrefix, len(cfg.Limiters)),
			}
			if in != "" || out != "" {
				limiter.Limits = append(limiter.Limits,
					fmt.Sprintf("%s %s %s", traffic.ServiceLimitKey, in, out))
			}
			if cin != "" || cout != "" {
				limiter.Limits = append(limiter.Limits,
					fmt.Sprintf("%s %s %s", traffic.ConnLimitKey, cin, cout))
			}
			service.Limiter = limiter.Name
			cfg.Limiters = append(cfg.Limiters, limiter)
			delete(mh, "limiter.in")
			delete(mh, "limiter.out")
			delete(mh, "limiter.conn.in")
			delete(mh, "limiter.conn.out")
		}

		if climit := mdutil.GetInt(md, "climiter"); climit > 0 {
			limiter := &config.LimiterConfig{
				Name:   fmt.Sprintf("%sclimiter-%d", namePrefix, len(cfg.CLimiters)),
				Limits: []string{fmt.Sprintf("%s %d", conn.GlobalLimitKey, climit)},
			}
			service.CLimiter = limiter.Name
			cfg.CLimiters = append(cfg.CLimiters, limiter)
			delete(mh, "climiter")
		}

		if rlimit := mdutil.GetFloat(md, "rlimiter"); rlimit > 0 {
			limiter := &config.LimiterConfig{
				Name:   fmt.Sprintf("%srlimiter-%d", namePrefix, len(cfg.RLimiters)),
				Limits: []string{fmt.Sprintf("%s %s", conn.GlobalLimitKey, strconv.FormatFloat(rlimit, 'f', -1, 64))},
			}
			service.RLimiter = limiter.Name
			cfg.RLimiters = append(cfg.RLimiters, limiter)
			delete(mh, "rlimiter")
		}
	}

	return cfg, nil
}

func cutHost(s string) (host, remain string) {
	if s == "" {
		return
	}

	n := strings.IndexByte(s, ':')
	start := n + 3
	end := strings.IndexAny(s[start:], "/?")
	if end < 0 {
		end = len(s)
	} else {
		end += start
	}
	// auth info
	if n = strings.LastIndexByte(s[start:end], '@'); n >= 0 {
		start += (n + 1)
	}
	host = s[start:end]

	remain = s[:start] + s[end:]

	return
}

func buildServiceConfig(url *url.URL) ([]*config.ServiceConfig, error) {
	namePrefix := ""
	if v := os.Getenv("_GOST_ID"); v != "" {
		namePrefix = fmt.Sprintf("go-%s@", v)
	}

	var handler, listener string
	schemes := strings.Split(url.Scheme, "+")
	if len(schemes) == 1 {
		handler = schemes[0]
		listener = schemes[0]
	}
	if len(schemes) == 2 {
		handler = schemes[0]
		listener = schemes[1]
	}

	addrs := xnet.AddrPortRange(url.Host).Addrs()
	if len(addrs) == 0 {
		addrs = append(addrs, url.Host)
	}

	var services []*config.ServiceConfig
	for _, addr := range addrs {
		services = append(services, &config.ServiceConfig{
			Addr: addr,
		})
	}

	if h := registry.HandlerRegistry().Get(handler); h == nil {
		handler = "auto"
	}
	if ln := registry.ListenerRegistry().Get(listener); ln == nil {
		listener = "tcp"
		if handler == "ssu" {
			listener = "udp"
		}
	}

	var nodes []*config.ForwardNodeConfig
	// forward mode
	if remotes := strings.Trim(url.EscapedPath(), "/"); remotes != "" {
		i := 0
		for _, addr := range strings.Split(remotes, ",") {
			addrs := xnet.AddrPortRange(addr).Addrs()
			if len(addrs) == 0 {
				addrs = append(addrs, addr)
			}
			for _, adr := range addrs {
				nodes = append(nodes, &config.ForwardNodeConfig{
					Name: fmt.Sprintf("%starget-%d", namePrefix, i),
					Addr: adr,
				})
				i++
			}
		}

		if handler != "relay" {
			if listener == "tcp" || listener == "udp" ||
				listener == "rtcp" || listener == "rudp" ||
				listener == "tun" || listener == "tap" ||
				listener == "dns" || listener == "unix" ||
				listener == "serial" {
				handler = listener
			} else {
				handler = "forward"
			}
		}
	}

	if len(nodes) > 0 {
		if len(services) == 1 {
			services[0].Forwarder = &config.ForwarderConfig{
				Nodes: nodes,
			}
		} else {
			for i, svc := range services {
				if len(nodes) == 1 {
					svc.Forwarder = &config.ForwarderConfig{
						Nodes: nodes,
					}
				} else {
					if i < len(nodes) {
						svc.Forwarder = &config.ForwarderConfig{
							Nodes: []*config.ForwardNodeConfig{nodes[i]},
						}
					}
				}
			}
		}
	}

	var auth *config.AuthConfig
	if url.User != nil {
		auth = &config.AuthConfig{
			Username: url.User.Username(),
		}
		auth.Password, _ = url.User.Password()
	}

	m := map[string]any{}
	for k, v := range url.Query() {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	md := mdx.NewMetadata(m)

	if sa := mdutil.GetString(md, "auth"); sa != "" {
		au, err := parseAuthFromCmd(sa)
		if err != nil {
			return nil, err
		}
		auth = au
	}
	delete(m, "auth")

	tlsConfig := &config.TLSConfig{
		CertFile: mdutil.GetString(md, "tls.certFile", "certFile", "cert"),
		KeyFile:  mdutil.GetString(md, "tls.keyFile", "keyFile", "key"),
		CAFile:   mdutil.GetString(md, "tls.caFile", "caFile", "ca"),
	}

	delete(m, "tls.certFile")
	delete(m, "certFile")
	delete(m, "cert")
	delete(m, "tls.keyFile")
	delete(m, "keyFile")
	delete(m, "key")
	delete(m, "tls.caFile")
	delete(m, "caFile")
	delete(m, "ca")

	if tlsConfig.CertFile == "" {
		tlsConfig = nil
	}

	if v := mdutil.GetString(md, "dns"); v != "" {
		m["dns"] = strings.Split(v, ",")
	}

	if v := mdutil.GetString(md, "interface"); v != "" {
		m["service.interface"] = v
		delete(m, "interface")
	}
	selector := parseSelector(m)

	serviceMd := map[string]any{}
	handleMd := map[string]any{}
	listenerMd := map[string]any{}
	for k, v := range m {
		if s, found := strings.CutPrefix(k, "service."); found {
			serviceMd[s] = v
			continue
		}
		if s, found := strings.CutPrefix(k, "handler."); found {
			handleMd[s] = v
			continue
		}
		if s, found := strings.CutPrefix(k, "listener."); found {
			listenerMd[s] = v
			continue
		}

		handleMd[k] = v
		listenerMd[k] = v
		serviceMd[k] = v
	}

	handlerCfg := &config.HandlerConfig{
		Type:     handler,
		Auth:     auth,
		Metadata: handleMd,
	}
	listenerCfg := &config.ListenerConfig{
		Type:     listener,
		TLS:      tlsConfig,
		Metadata: listenerMd,
	}
	if listenerCfg.Type == "ssh" || listenerCfg.Type == "sshd" {
		handlerCfg.Auth = nil
		listenerCfg.Auth = auth
	}

	for _, svc := range services {
		if svc.Forwarder != nil {
			svc.Forwarder.Selector = selector
		}
		svc.Handler = handlerCfg
		svc.Listener = listenerCfg
		svc.Metadata = serviceMd
	}

	return services, nil
}

func buildNodeConfig(url *url.URL, m map[string]any) (*config.NodeConfig, error) {
	var connector, dialer string
	schemes := strings.Split(url.Scheme, "+")
	if len(schemes) == 1 {
		connector = schemes[0]
		dialer = schemes[0]
	}
	if len(schemes) == 2 {
		connector = schemes[0]
		dialer = schemes[1]
	}

	md := mdx.NewMetadata(m)

	if c := registry.ConnectorRegistry().Get(connector); c == nil {
		connector = "http"
	}
	if d := registry.DialerRegistry().Get(dialer); d == nil {
		dialer = "tcp"
		if connector == "ssu" {
			dialer = "udp"
		}
	}

	var auth *config.AuthConfig
	if url.User != nil {
		auth = &config.AuthConfig{
			Username: url.User.Username(),
		}
		auth.Password, _ = url.User.Password()
	}

	if sauth := mdutil.GetString(md, "auth"); sauth != "" && auth == nil {
		au, err := parseAuthFromCmd(sauth)
		if err != nil {
			return nil, err
		}
		auth = au
	}
	delete(m, "auth")

	tlsConfig := &config.TLSConfig{
		CertFile:   mdutil.GetString(md, "tls.certFile", "certFile", "cert"),
		KeyFile:    mdutil.GetString(md, "tls.keyFile", "keyFile", "key"),
		CAFile:     mdutil.GetString(md, "tls.caFile", "caFile", "ca"),
		Secure:     mdutil.GetBool(md, "tls.secure", "secure"),
		ServerName: mdutil.GetString(md, "tls.servername", "servername"),
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = url.Hostname()
	}

	delete(m, "tls.certFile")
	delete(m, "certFile")
	delete(m, "cert")
	delete(m, "tls.keyFile")
	delete(m, "keyFile")
	delete(m, "key")
	delete(m, "tls.caFile")
	delete(m, "caFile")
	delete(m, "ca")
	delete(m, "tls.secure")
	delete(m, "secure")
	delete(m, "tls.servername")
	delete(m, "serverName")

	if !tlsConfig.Secure && tlsConfig.CertFile == "" && tlsConfig.CAFile == "" && tlsConfig.ServerName == "" {
		tlsConfig = nil
	}

	nodeMd := map[string]any{}
	connectorMd := map[string]any{}
	dialerMd := map[string]any{}
	for k, v := range m {
		if s, found := strings.CutPrefix(k, "node."); found {
			nodeMd[s] = v
			continue
		}
		if s, found := strings.CutPrefix(k, "connector."); found {
			connectorMd[s] = v
			continue
		}
		if s, found := strings.CutPrefix(k, "dialer."); found {
			dialerMd[s] = v
			continue
		}

		connectorMd[k] = v
		dialerMd[k] = v
		nodeMd[k] = v
	}

	node := &config.NodeConfig{
		Addr:     url.Host,
		Metadata: nodeMd,
	}
	node.Connector = &config.ConnectorConfig{
		Type:     connector,
		Auth:     auth,
		Metadata: connectorMd,
	}
	node.Dialer = &config.DialerConfig{
		Type:     dialer,
		TLS:      tlsConfig,
		Metadata: dialerMd,
	}

	if node.Dialer.Type == "ssh" || node.Dialer.Type == "sshd" {
		node.Connector.Auth = nil
		node.Dialer.Auth = auth
	}

	return node, nil
}

func Norm(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrInvalidCmd
	}

	if s[0] == ':' || !strings.Contains(s, "://") {
		s = "auto://" + s
	}

	url, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if url.Scheme == "https" {
		url.Scheme = "http+tls"
	}

	return url, nil
}

func parseAuthFromCmd(sa string) (*config.AuthConfig, error) {
	v, err := base64.StdEncoding.DecodeString(sa)
	if err != nil {
		return nil, err
	}
	cs := string(v)
	n := strings.IndexByte(cs, ':')
	if n < 0 {
		return &config.AuthConfig{
			Username: cs,
		}, nil
	}

	return &config.AuthConfig{
		Username: cs[:n],
		Password: cs[n+1:],
	}, nil
}

func parseSelector(m map[string]any) *config.SelectorConfig {
	md := mdx.NewMetadata(m)
	strategy := mdutil.GetString(md, "strategy")
	maxFails := mdutil.GetInt(md, "maxFails", "max_fails")
	failTimeout := mdutil.GetDuration(md, "failTimeout", "fail_timeout")
	if strategy == "" && maxFails <= 0 && failTimeout <= 0 {
		return nil
	}
	if strategy == "" {
		strategy = "round"
	}
	if maxFails <= 0 {
		maxFails = 1
	}
	if failTimeout <= 0 {
		failTimeout = 30 * time.Second
	}

	delete(m, "strategy")
	delete(m, "maxFails")
	delete(m, "max_fails")
	delete(m, "failTimeout")
	delete(m, "fail_timeout")

	return &config.SelectorConfig{
		Strategy:    strategy,
		MaxFails:    maxFails,
		FailTimeout: failTimeout,
	}
}
