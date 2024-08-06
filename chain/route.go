package chain

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metrics"
	"github.com/go-gost/core/selector"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/dialer"
	"github.com/go-gost/x/internal/net/udp"
	xmetrics "github.com/go-gost/x/metrics"
)

var (
	ErrEmptyRoute = errors.New("empty route")
)

var (
	DefaultRoute chain.Route = &defaultRoute{}
)

// defaultRoute is a Route without nodes.
type defaultRoute struct{}

func (*defaultRoute) Dial(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
	var options chain.DialOptions
	for _, opt := range opts {
		opt(&options)
	}

	netd := dialer.Dialer{
		Interface: options.Interface,
		Netns:     options.Netns,
		Logger:    options.Logger,
	}
	if options.SockOpts != nil {
		netd.Mark = options.SockOpts.Mark
	}

	return netd.Dial(ctx, network, address)
}

func (*defaultRoute) Bind(ctx context.Context, network, address string, opts ...chain.BindOption) (net.Listener, error) {
	var options chain.BindOptions
	for _, opt := range opts {
		opt(&options)
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		addr, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			return nil, err
		}
		return net.ListenTCP(network, addr)
	case "udp", "udp4", "udp6":
		addr, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			return nil, err
		}
		conn, err := net.ListenUDP(network, addr)
		if err != nil {
			return nil, err
		}
		logger := logger.Default().WithFields(map[string]any{
			"network": network,
			"address": address,
		})
		ln := udp.NewListener(conn, &udp.ListenConfig{
			Backlog:        options.Backlog,
			ReadQueueSize:  options.UDPDataQueueSize,
			ReadBufferSize: options.UDPDataBufferSize,
			TTL:            options.UDPConnTTL,
			Keepalive:      true,
			Logger:         logger,
		})
		return ln, err
	default:
		err := fmt.Errorf("network %s unsupported", network)
		return nil, err
	}
}

func (r *defaultRoute) Nodes() []*chain.Node {
	return nil
}

type RouteOptions struct {
	Chain chain.Chainer
}

type RouteOption func(*RouteOptions)

func ChainRouteOption(c chain.Chainer) RouteOption {
	return func(o *RouteOptions) {
		o.Chain = c
	}
}

type chainRoute struct {
	nodes   []*chain.Node
	options RouteOptions
}

func NewRoute(opts ...RouteOption) *chainRoute {
	var options RouteOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	return &chainRoute{
		options: options,
	}
}

func (r *chainRoute) addNode(nodes ...*chain.Node) {
	r.nodes = append(r.nodes, nodes...)
}

func (r *chainRoute) Dial(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
	if len(r.Nodes()) == 0 {
		return DefaultRoute.Dial(ctx, network, address, opts...)
	}

	var options chain.DialOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	conn, err := r.connect(ctx, options.Logger)
	if err != nil {
		return nil, err
	}

	cc, err := r.getNode(len(r.Nodes())-1).Options().Transport.Connect(ctx, conn, network, address)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, err
	}
	return cc, nil
}

func (r *chainRoute) Bind(ctx context.Context, network, address string, opts ...chain.BindOption) (net.Listener, error) {
	if len(r.Nodes()) == 0 {
		return DefaultRoute.Bind(ctx, network, address, opts...)
	}

	var options chain.BindOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	conn, err := r.connect(ctx, options.Logger)
	if err != nil {
		return nil, err
	}

	ln, err := r.getNode(len(r.Nodes())-1).Options().Transport.Bind(ctx,
		conn, network, address,
		connector.BacklogBindOption(options.Backlog),
		connector.MuxBindOption(options.Mux),
		connector.UDPConnTTLBindOption(options.UDPConnTTL),
		connector.UDPDataBufferSizeBindOption(options.UDPDataBufferSize),
		connector.UDPDataQueueSizeBindOption(options.UDPDataQueueSize),
	)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return ln, nil
}

func (r *chainRoute) connect(ctx context.Context, logger logger.Logger) (conn net.Conn, err error) {
	network := "ip"
	node := r.nodes[0]

	defer func() {
		if r.options.Chain != nil {
			var marker selector.Marker
			if m, ok := r.options.Chain.(selector.Markable); ok && m != nil {
				marker = m.Marker()
			}
			var name string
			if cn, _ := r.options.Chain.(chainNamer); cn != nil {
				name = cn.Name()
			}
			// chain error
			if err != nil {
				if marker != nil {
					marker.Mark()
				}
				if v := xmetrics.GetCounter(xmetrics.MetricChainErrorsCounter,
					metrics.Labels{"chain": name, "node": node.Name}); v != nil {
					v.Inc()
				}
				return
			}

			if marker != nil {
				marker.Reset()
			}
		}
	}()

	addr, err := xnet.Resolve(ctx, network, node.Addr, node.Options().Resolver, node.Options().HostMapper, logger)
	marker := node.Marker()
	if err != nil {
		if marker != nil {
			marker.Mark()
		}
		return
	}

	start := time.Now()
	cc, err := node.Options().Transport.Dial(ctx, addr)
	if err != nil {
		if marker != nil {
			marker.Mark()
		}
		return
	}

	cn, err := node.Options().Transport.Handshake(ctx, cc)
	if err != nil {
		cc.Close()
		if marker != nil {
			marker.Mark()
		}
		return
	}
	if marker != nil {
		marker.Reset()
	}

	if r.options.Chain != nil {
		var name string
		if cn, _ := r.options.Chain.(chainNamer); cn != nil {
			name = cn.Name()
		}
		if v := xmetrics.GetObserver(xmetrics.MetricNodeConnectDurationObserver,
			metrics.Labels{"chain": name, "node": node.Name}); v != nil {
			v.Observe(time.Since(start).Seconds())
		}
	}

	preNode := node
	for _, node := range r.nodes[1:] {
		marker := node.Marker()
		addr, err = xnet.Resolve(ctx, network, node.Addr, node.Options().Resolver, node.Options().HostMapper, logger)
		if err != nil {
			cn.Close()
			if marker != nil {
				marker.Mark()
			}
			return
		}
		cc, err = preNode.Options().Transport.Connect(ctx, cn, "tcp", addr)
		if err != nil {
			cn.Close()
			if marker != nil {
				marker.Mark()
			}
			return
		}
		cc, err = node.Options().Transport.Handshake(ctx, cc)
		if err != nil {
			cn.Close()
			if marker != nil {
				marker.Mark()
			}
			return
		}
		if marker != nil {
			marker.Reset()
		}

		cn = cc
		preNode = node
	}

	conn = cn
	return
}

func (r *chainRoute) getNode(index int) *chain.Node {
	if r == nil || len(r.Nodes()) == 0 || index < 0 || index >= len(r.Nodes()) {
		return nil
	}
	return r.nodes[index]
}

func (r *chainRoute) Nodes() []*chain.Node {
	if r != nil {
		return r.nodes
	}
	return nil
}
