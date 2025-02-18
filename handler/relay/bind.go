package relay

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/relay"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/udp"
	"github.com/go-gost/x/internal/util/mux"
	relay_util "github.com/go-gost/x/internal/util/relay"
	traffic_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xservice "github.com/go-gost/x/service"
)

func (h *relayHandler) handleBind(ctx context.Context, conn net.Conn, network, address string, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"dst": fmt.Sprintf("%s/%s", address, network),
		"cmd": "bind",
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), address)

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

	if network == "tcp" {
		return h.bindTCP(ctx, conn, network, address, log)
	} else {
		return h.bindUDP(ctx, conn, network, address, log)
	}
}

func (h *relayHandler) bindTCP(ctx context.Context, conn net.Conn, network, address string, log logger.Logger) error {
	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	lc := xnet.ListenConfig{
		Netns: h.options.Netns,
	}
	ln, err := lc.Listen(ctx, network, address) // strict mode: if the port already in use, it will return error
	if err != nil {
		log.Error(err)
		resp.Status = relay.StatusServiceUnavailable
		resp.WriteTo(conn)
		return err
	}
	defer ln.Close()

	serviceName := fmt.Sprintf("%s-ep-%s", h.options.Service, ln.Addr())
	log = log.WithFields(map[string]any{
		"service":  serviceName,
		"listener": "tcp",
		"handler":  "ep-tcp",
		"bind":     fmt.Sprintf("%s/%s", ln.Addr(), ln.Addr().Network()),
	})

	af := &relay.AddrFeature{}
	if err := af.ParseFrom(ln.Addr().String()); err != nil {
		log.Warn(err)
	}
	resp.Features = append(resp.Features, af)
	if _, err := resp.WriteTo(conn); err != nil {
		log.Error(err)
		return err
	}

	// Upgrade connection to multiplex session.
	session, err := mux.ClientSession(conn, h.md.muxCfg)
	if err != nil {
		log.Error(err)
		return err
	}
	defer session.Close()

	epListener := newTCPListener(ln,
		listener.AddrOption(address),
		listener.ServiceOption(serviceName),
		listener.TrafficLimiterOption(h.options.Limiter),
		listener.LoggerOption(log.WithFields(map[string]any{
			"kind": "listener",
		})),
	)
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
	log.Debugf("bind on %s/%s OK", ln.Addr(), ln.Addr().Network())

	go func() {
		defer srv.Close()
		for {
			conn, err := session.Accept()
			if err != nil {
				log.Error(err)
				return
			}
			conn.Close() // we do not handle incoming connections.
		}
	}()

	return srv.Serve()
}

func (h *relayHandler) bindUDP(ctx context.Context, conn net.Conn, network, address string, log logger.Logger) error {
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
		"bind":     fmt.Sprintf("%s/%s", pc.LocalAddr(), pc.LocalAddr().Network()),
	})
	pc = metrics.WrapPacketConn(serviceName, pc)
	// pc = admission.WrapPacketConn(l.options.Admission, pc)
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

	log = log.WithFields(map[string]any{
		"bind": pc.LocalAddr().String(),
	})
	log.Debugf("bind on %s OK", pc.LocalAddr())

	r := udp.NewRelay(relay_util.UDPTunServerConn(conn), pc).
		WithBypass(h.options.Bypass).
		WithLogger(log)

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), pc.LocalAddr())
	r.Run(ctx)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), pc.LocalAddr())
	return nil
}
