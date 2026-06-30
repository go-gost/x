package relay

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/resolver"
	"github.com/go-gost/relay"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/udp"
	"github.com/go-gost/x/internal/util/mux"
	relay_util "github.com/go-gost/x/internal/util/relay"
	traffic_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	xservice "github.com/go-gost/x/service"
)

// handleBind processes a relay CmdBind request.
//
// BIND mode is used for reverse-proxy scenarios: the client asks the relay
// handler to listen on a local port, then forwards inbound connections back
// to the client over a mux session.
//
// Flow:
//
//	handleBind()
//	├─ 1. Wrap traffic limiter + stats
//	├─ 2. Check BIND is enabled
//	├─ 3. TCP BIND → bindTCP()
//	│   ├─ net.Listen on the specified address
//	│   ├─ Return the listening address via relay.Response
//	│   ├─ Upgrade the connection to a mux session
//	│   ├─ Start tcpHandler + tcpListener as an internal service
//	│   │   ├─ tcpHandler: gets a stream from mux session → writes AddrFeature
//	│   │   └─ tcpListener: accepts local TCP connections
//	│   ├─ Goroutine: drain unexpected mux sessions
//	│   └─ service.Serve() blocks
//	└─ 4. UDP BIND → bindUDP()
//	    ├─ net.ListenPacket on the UDP port
//	    ├─ Return the listening address
//	    └─ Create udp.Relay for datagram relay
//
// Key design:
//   - TCP BIND uses mux: each inbound connection gets an independent mux stream
//     carrying a relay AddrFeature identifying the peer address.
//   - UDP BIND uses udp.Relay directly, bypassing mux.
func (h *relayHandler) handleBind(ctx context.Context, conn net.Conn, network, address string, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"dst": address,
		"cmd": "bind",
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), address)

	// --- Traffic limiter + stats wrapper ---
	{
		clientID := ctxvalue.ClientIDFromContext(ctx)
		rw := traffic_wrapper.WrapReadWriter(
			h.limiter,
			conn,
			string(clientID),
			limiter.ScopeOption(limiter.ScopeClient),
			limiter.ServiceOption(h.options.Service),
			limiter.NetworkOption(network),
			limiter.AddrOption(address),
			limiter.ClientOption(string(clientID)),
			limiter.SrcOption(conn.RemoteAddr().String()),
		)
		if h.options.Observer != nil {
			pstats := h.stats.Stats(string(clientID))
			pstats.Add(stats.KindTotalConns, 1)
			pstats.Add(stats.KindCurrentConns, 1)
			defer pstats.Add(stats.KindCurrentConns, -1)
			rw = stats_wrapper.WrapReadWriter(rw, pstats)
		}

		conn = xnet.NewReadWriteConn(rw, rw, conn)
	}

	// Check whether BIND is enabled in config.
	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	if !h.md.enableBind {
		resp.Status = relay.StatusForbidden
		log.Error("relay: BIND is disabled")
		_, err := resp.WriteTo(conn)
		return err
	}

	switch network {
	case "tcp", "tcp4", "tcp6", "unix":
		return h.bindTCP(ctx, conn, network, address, ro, log)
	case "udp", "udp4", "udp6":
		return h.bindUDP(ctx, conn, network, address, ro, log)
	default:
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		return fmt.Errorf("network %s is unsupported", network)
	}
}

// bindTCP implements TCP BIND mode.
//
// Detailed flow:
//
//	bindTCP()
//	├─ 1. net.Listen on the specified TCP address
//	├─ 2. Write the listening address into relay.Response, send to client
//	├─ 3. Upgrade the client connection to a mux session
//	│     (mux multiplexes multiple independent streams over one TCP conn)
//	├─ 4. Create internal tcpListener + tcpHandler + Service
//	│   ├─ tcpListener: wraps net.Listener with proxyproto/metrics/admission
//	│   ├─ tcpHandler: on each inbound connection:
//	│   │   ├─ Gets a stream from the mux session
//	│   │   ├─ Writes the inbound peer address as AddrFeature on the stream
//	│   │   └─ Pipes data bidirectionally (local conn ↔ mux stream)
//	│   └─ Service: wraps listener + handler, blocks on Serve()
//	├─ 5. Goroutine: accept and discard unexpected mux connections
//	└─ 6. srv.Serve() blocks until shutdown
//
// The client receives forwarded connections as streams on the mux session.
// Each stream carries a relay.AddrFeature identifying the original peer.
func (h *relayHandler) bindTCP(ctx context.Context, conn net.Conn, network, address string, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	lc := xnet.ListenConfig{
		Netns: h.options.Netns,
	}
	ln, err := lc.Listen(ctx, network, address) // strict: port-in-use returns error
	if err != nil {
		log.Error(err)
		resp.Status = relay.StatusServiceUnavailable
		resp.WriteTo(conn)
		return err
	}
	defer ln.Close()

	// Internal service name: "<main-service>-ep-<listen-address>"
	serviceName := fmt.Sprintf("%s-ep-%s", h.options.Service, ln.Addr())
	log = log.WithFields(map[string]any{
		"service":  serviceName,
		"listener": network,
		"handler":  "ep-tcp",
		"bind":     fmt.Sprintf("%s/%s", ln.Addr(), ln.Addr().Network()),
		"src":      ln.Addr().String(),
	})
	ro.SrcAddr = ln.Addr().String()

	// Return the listening address to the client.
	af := &relay.AddrFeature{}
	if err := af.ParseFrom(ln.Addr().String()); err != nil {
		log.Warn(err)
	}
	resp.Features = append(resp.Features, af)
	if _, err := resp.WriteTo(conn); err != nil {
		log.Error(err)
		return err
	}

	// Upgrade the client connection to a mux session.
	session, err := mux.ClientSession(conn, h.md.muxCfg)
	if err != nil {
		log.Error(err)
		return err
	}
	defer session.Close()

	// Internal endpoint listener (proxyproto → metrics → admission layers).
	epListener := newTCPListener(ln,
		listener.AddrOption(address),
		listener.ServiceOption(serviceName),
		listener.TrafficLimiterOption(h.options.Limiter),
		listener.LoggerOption(log.WithFields(map[string]any{
			"kind": "listener",
		})),
	)
	// Internal endpoint handler — on each inbound connection:
	//   1. Gets a stream from the mux session
	//   2. Writes the peer address as AddrFeature on the mux stream
	//   3. Pipes data bidirectionally
	epHandler := newTCPHandler(session,
		handler.ServiceOption(serviceName),
		handler.LoggerOption(log.WithFields(map[string]any{
			"kind": "handler",
		})),
	)
	srv := xservice.NewService(
		serviceName, epListener, epHandler,
		xservice.LoggerOption(log.WithFields(map[string]any{
			"kind": "service",
		})),
	)

	log = log.WithFields(map[string]any{})
	log.Infof("bind on %s/%s OK", ln.Addr(), ln.Addr().Network())

	// Goroutine: accept and discard unexpected mux connections.
	// Normal inbound connections are handled by tcpHandler via session.GetConn().
	go func() {
		defer srv.Close()
		for {
			conn, err := session.Accept()
			if err != nil {
				log.Error(err)
				return
			}
			conn.Close() // unexpected inbound — we don't handle these
		}
	}()

	return srv.Serve()
}

// bindUDP implements UDP BIND mode.
//
// Flow:
//  1. net.ListenPacket on the specified UDP address.
//  2. Return the listening address to the client.
//  3. Create a udp.Relay for bidir datagram relay between client and local port.
//
// Unlike TCP BIND, UDP BIND does not use mux. It relays datagrams directly via
// udp.Relay, wrapping the stream connection as UDPTunServerConn for datagram
// framing over the stream.
func (h *relayHandler) bindUDP(ctx context.Context, conn net.Conn, network, address string, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	lc := xnet.ListenConfig{
		Netns: h.options.Netns,
	}
	pc, err := lc.ListenPacket(ctx, network, address)
	if err != nil {
		log.Error(err)
		return err
	}

	serviceName := fmt.Sprintf("%s-ep-%s", h.options.Service, pc.LocalAddr())
	log = log.WithFields(map[string]any{
		"service":  serviceName,
		"listener": "udp",
		"handler":  "ep-udp",
		"bind":     pc.LocalAddr().String(),
		"src":      pc.LocalAddr().String(),
	})
	ro.SrcAddr = pc.LocalAddr().String()

	// lc.ListenPacket returns a raw *net.UDPConn which can't resolve
	// domainAddr returned by UDPTunServerConn.ReadFrom for domain targets.
	// Wrap it so domains resolve through hostMapper → configured resolver
	// → system DNS instead of failing WriteTo with an unknown addr type.
	if _, ok := pc.(*net.UDPConn); ok {
		var r resolver.Resolver
		var hm hosts.HostMapper
		if h.options.Router != nil {
			r = h.options.Router.Options().Resolver
			hm = h.options.Router.Options().HostMapper
		}
		pc = &resolvePacketConn{
			PacketConn: pc,
			resolver:   r,
			hostMapper: hm,
		}
	}

	pc = metrics.WrapPacketConn(serviceName, pc)
	// pc = limiter.WrapPacketConn(l.options.TrafficLimiter, pc)

	defer pc.Close()

	af := &relay.AddrFeature{}
	if err := af.ParseFrom(pc.LocalAddr().String()); err != nil {
		log.Warn(err)
	}
	resp.Features = append(resp.Features, af)
	if _, err := resp.WriteTo(conn); err != nil {
		log.Error(err)
		return err
	}

	log.Infof("bind on %s OK", pc.LocalAddr())

	// UDPTunServerConn wraps the stream connection in datagram mode.
	r := udp.NewRelay(relay_util.UDPTunServerConn(conn), pc).
		WithService(h.options.Service).
		WithBypass(h.options.Bypass).
		WithBufferSize(h.md.udpBufferSize).
		WithLogger(log)

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), pc.LocalAddr())
	r.Run(ctx)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), pc.LocalAddr())
	return nil
}

// resolvePacketConn wraps a net.PacketConn and resolves domain addresses
// in WriteTo calls through hostMapper → configured resolver → system DNS.
//
// After udpTunConn.ReadFrom returns a domainAddr for ATYP=DOMAINNAME
// datagrams, a raw *net.UDPConn cannot consume it (WriteTo needs *net.UDPAddr).
// This wrapper resolves the domain before forwarding.
type resolvePacketConn struct {
	net.PacketConn
	resolver   resolver.Resolver
	hostMapper hosts.HostMapper
}

func (c *resolvePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return c.PacketConn.WriteTo(b, addr)
	}
	if net.ParseIP(host) != nil {
		return c.PacketConn.WriteTo(b, addr)
	}

	var ips []net.IP
	if c.hostMapper != nil {
		ips, _ = c.hostMapper.Lookup(context.Background(), "ip", host)
	}
	if len(ips) == 0 && c.resolver != nil {
		ips, _ = c.resolver.Resolve(context.Background(), "ip", host)
	}
	if len(ips) == 0 {
		ips, _ = net.LookupIP(host)
	}
	if len(ips) == 0 {
		return 0, fmt.Errorf("relay udp: cannot resolve %s", host)
	}

	ip := ips[0]
	for _, candidate := range ips {
		if candidate.To4() != nil {
			ip = candidate
			break
		}
	}
	port, _ := strconv.Atoi(portStr)
	return c.PacketConn.WriteTo(b, &net.UDPAddr{IP: ip, Port: port})
}
