package chain

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
)

// Router is the top-level routing entry point. It resolves addresses,
// selects routes through the configured chain, retries on failure, and
// records telemetry (address events, errors, metrics).
type Router struct {
	options chain.RouterOptions
}

// NewRouter creates a Router with the given options. Defaults: 15s timeout,
// a logger with kind "router" if none is provided.
func NewRouter(opts ...chain.RouterOption) *Router {
	r := &Router{}
	for _, opt := range opts {
		if opt != nil {
			opt(&r.options)
		}
	}
	if r.options.Timeout == 0 {
		r.options.Timeout = 15 * time.Second
	}

	if r.options.Logger == nil {
		r.options.Logger = logger.Default().WithFields(map[string]any{"kind": "router"})
	}
	return r
}

func (r *Router) Options() *chain.RouterOptions {
	if r == nil {
		return nil
	}
	return &r.options
}

// Dial establishes a connection to the target address through the configured
// chain. It resolves the address, records the dial event, retries up to
// Retries+1 times, and returns the resulting connection.
// For UDP networks the returned connection is wrapped as a PacketConn if the
// underlying transport does not already implement net.PacketConn.
func (r *Router) Dial(ctx context.Context, network, address string, opts ...chain.DialOption) (conn net.Conn, err error) {
	host := address
	if h, _, _ := net.SplitHostPort(address); h != "" {
		host = h
	}
	r.record(ctx, recorder.RecorderServiceRouterDialAddress, []byte(host))

	log := r.options.Logger.WithFields(map[string]any{
		"sid": xctx.SidFromContext(ctx),
	})

	conn, err = r.dial(ctx, network, address, log, opts...)
	if err != nil {
		r.record(ctx, recorder.RecorderServiceRouterDialAddressError, []byte(host))
		return
	}

	if network == "udp" || network == "udp4" || network == "udp6" {
		if _, ok := conn.(net.PacketConn); !ok {
			return &packetConn{conn}, nil
		}
	}
	return
}

func (r *Router) record(ctx context.Context, name string, data []byte) error {
	if len(data) == 0 {
		return nil
	}

	for _, rec := range r.options.Recorders {
		if rec.Record == name {
			return rec.Recorder.Record(ctx, data)
		}
	}
	return nil
}

func (r *Router) dial(ctx context.Context, network, address string, log logger.Logger, callerOpts ...chain.DialOption) (conn net.Conn, err error) {
	count := r.options.Retries + 1
	if count <= 0 {
		count = 1
	}

	log.Debugf("dial %s/%s", address, network)

	for i := 0; i < count; i++ {
		func() {
			ctx := ctx
			if r.options.Timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, r.options.Timeout)
				defer cancel()
			}

			buf := ictx.BufferFromContext(ctx)
			if buf != nil {
				buf.Reset()
			}

			var ipAddr string
			ipAddr, err = xnet.Resolve(ctx, "ip", address, r.options.Resolver, r.options.HostMapper, log)
			if err != nil {
				log.Error(err)
				return
			}

			if buf != nil {
				buf.Reset()
			}

			var route chain.Route
			if r.options.Chain != nil {
				route = r.options.Chain.Route(ctx, network, ipAddr, chain.WithHostRouteOption(address))
			}

			if buf == nil {
				buf = &bytes.Buffer{}
			}
			for _, node := range routePath(route) {
				fmt.Fprintf(buf, "%s@%s > ", node.Name, node.Addr)
			}
			fmt.Fprintf(buf, "%s", ipAddr)
			log.Debugf("route(retry=%d) %s", i, buf.String())

			if route == nil {
				route = DefaultRoute
			}
			ifceName := r.options.IfceName
			if strings.Contains(ifceName, "auto") {
				// "auto" triggers per-connection interface detection: the
				// ingress IP (conn.LocalAddr()) is used as the bind address,
				// ensuring egress traffic leaves via the same interface that
				// received the connection — the "source-in source-out"
				// pattern for multi-homed hosts.
				if dstAddr := xctx.DstAddrFromContext(ctx); dstAddr != nil {
					if host, _, _ := net.SplitHostPort(dstAddr.String()); host != "" &&
						host != "0.0.0.0" && host != "::" {
						// Replace only exact "auto" tokens in the
						// comma-separated interface list.
						parts := strings.Split(ifceName, ",")
						for i, p := range parts {
							if p == "auto" {
								parts[i] = host
							}
						}
						ifceName = strings.Join(parts, ",")
					}
				}
				if strings.Contains(ifceName, "auto") {
					log.Debugf("auto interface: no suitable ingress address, keeping literal %q", ifceName)
				}
			}
			conn, err = route.Dial(ctx, network, ipAddr,
				append([]chain.DialOption{
					chain.InterfaceDialOption(ifceName),
					chain.NetnsDialOption(r.options.Netns),
					chain.SockOptsDialOption(r.options.SockOpts),
					chain.LoggerDialOption(log),
				}, callerOpts...)...,
			)
			if err == nil {
				return
			}
			log.Errorf("route(retry=%d) %s", i, err)
		}()
		if conn != nil || err == nil {
			break
		}
	}

	return
}

// Bind creates a listener bound to the given address through the configured
// chain. It retries up to Retries+1 times on failure.
func (r *Router) Bind(ctx context.Context, network, address string, opts ...chain.BindOption) (ln net.Listener, err error) {
	count := r.options.Retries + 1
	if count <= 0 {
		count = 1
	}

	log := r.options.Logger.WithFields(map[string]any{
		"sid": xctx.SidFromContext(ctx),
	})

	log.Debugf("bind on %s/%s", address, network)

	for i := 0; i < count; i++ {
		func() {
			ctx := ctx
			if r.options.Timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, r.options.Timeout)
				defer cancel()
			}

			var route chain.Route
			if r.options.Chain != nil {
				route = r.options.Chain.Route(ctx, network, address)
				if route == nil || len(route.Nodes()) == 0 {
					err = ErrEmptyRoute
					return
				}
			}

			if log.IsLevelEnabled(logger.DebugLevel) {
				buf := bytes.Buffer{}
				for _, node := range routePath(route) {
					fmt.Fprintf(&buf, "%s@%s > ", node.Name, node.Addr)
				}
				fmt.Fprintf(&buf, "%s", address)
				log.Debugf("route(retry=%d) %s", i, buf.String())
			}

			if route == nil {
				route = DefaultRoute
			}
			ln, err = route.Bind(ctx, network, address, opts...)
			if err == nil {
				return
			}
			log.Errorf("route(retry=%d) %s", i, err)
		}()
		if ln != nil || err == nil {
			break
		}
	}

	return
}

func routePath(route chain.Route) (path []*chain.Node) {
	if route == nil {
		return
	}
	for _, node := range route.Nodes() {
		if tr := node.Options().Transport; tr != nil {
			path = append(path, routePath(tr.Options().Route)...)
		}
		path = append(path, node)
	}
	return
}

type packetConn struct {
	net.Conn
}

func (c *packetConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	n, err = c.Read(b)
	addr = c.Conn.RemoteAddr()
	return
}

func (c *packetConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	return c.Write(b)
}
