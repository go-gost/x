// Package tunnel implements a reverse proxy tunnel handler for NAT traversal.
//
// Architecture overview
//
// The tunnel handler is deployed on the public-facing (server) side. It acts as a
// bridge between external clients and internal services behind NAT/firewall.
//
// There are two main roles:
//
//  1. Internal client (CmdBind) — connects to the tunnel handler and registers a
//     multiplexed session (mux.Session via smux) as a Connector. Once bound, this
//     client passively waits to receive streams from the public side.
//
//  2. Public entrypoints (CmdConnect + entrypoint) — accept incoming requests from
//     the Internet and forward them through the tunnel to the internal client via
//     mux streams (OpenStream).
//
// Data flow (normal direction: public → internal):
//
//	Public request → tunnelHandler.Handle() / entrypoint.Handle()
//	  → Dialer.Dial()
//	    → ConnectorPool.Get() → Tunnel.GetConnector() → Connector.GetConn()
//	      → mux.Session.OpenStream()  ← creates stream to internal side
//	  → Pipe(publicConn, muxStream)
//
// Internal client side:
//
//	mux.Session.AcceptStream()  ← receives the stream
//	  → processes request, sends response back through the same stream
//
// Connector lifecycle (CmdBind):
//
//	Internal client sends CmdBind → handleBind() creates mux.ClientSession
//	  → NewConnector (stores session, starts waitClose goroutine)
//	  → ConnectorPool.Add() → Tunnel.AddConnector()
//	  → ingress rules + SD service registered
//
// The waitClose goroutine (Connector.waitClose) discards unexpected inbound
// streams on the Connector's mux session. This is a safety guard — normal
// request streams arrive via OpenStream from the public side and are handled
// by the internal client's Accept loop, NOT by waitClose.
//
// Entrypoint protocol dispatch (first-byte sniffing):
//
//	  relay.Version1 (0x52 'R') → handleConnect (relay protocol)
//	  dissector.Handshake (0x16) → handleTLS (TLS passthrough)
//	  otherwise                  → handleHTTP (HTTP forward proxy)
//
// SD fallback: when ConnectorPool.Get() returns nil (no local tunnel registered),
// Dialer queries service discovery for a remote node address and establishes a
// direct TCP connection, bypassing the mux session entirely.
package tunnel

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/service"
	"github.com/go-gost/relay"
	xctx "github.com/go-gost/x/ctx"
	stats_util "github.com/go-gost/x/internal/util/stats"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	cache_limiter "github.com/go-gost/x/limiter/traffic/cache"
	"github.com/go-gost/x/registry"
	"github.com/google/uuid"
)

var (
	// ErrBadVersion is returned when the relay request has an unsupported
	// protocol version.
	ErrBadVersion = errors.New("bad version")
	// ErrUnknownCmd is returned when the relay request command is not
	// CmdConnect or CmdBind.
	ErrUnknownCmd = errors.New("unknown command")
	// ErrTunnelID is returned when the relay request has a zero/invalid
	// tunnel ID feature.
	ErrTunnelID = errors.New("invalid tunnel ID")
	// ErrTunnelNotAvailable is returned when no local connector or SD
	// service is available for the requested tunnel.
	ErrTunnelNotAvailable = errors.New("tunnel not available")
	// ErrUnauthorized is returned when the relay request's user/pass
	// authentication fails against the configured Auther.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrTunnelRoute is returned when the tunnel route cannot be
	// resolved (no ingress rule matches the host).
	ErrTunnelRoute = errors.New("no route to host")
	// ErrPrivateTunnel is returned when the resolved tunnel is private
	// ($-prefixed) and the connection is from a public entrypoint.
	ErrPrivateTunnel = errors.New("private tunnel")
)

func init() {
	registry.HandlerRegistry().Register("tunnel", NewHandler)
}

// tunnelHandler is the relay-based tunnel handler. It accepts relay-protocol
// connections from internal clients (CmdBind) and from public sources
// (CmdConnect), bridging them through a mux-based multiplex session.
type tunnelHandler struct {
	// id is a UUID-generated unique identifier for this handler instance,
	// used to distinguish this node in multi-node deployments.
	id          string
	options     handler.Options
	pool        *ConnectorPool
	entrypoints []service.Service
	md          metadata
	log         logger.Logger
	stats       *stats_util.HandlerStats
	limiter     traffic.TrafficLimiter
	cancel      context.CancelFunc
}

// NewHandler creates a new tunnel handler.
//
// Registered as "tunnel" in the handler registry (init()). The handler
// processes relay-protocol requests and supports two commands:
// CmdConnect (forward a public connection through a tunnel stream) and
// CmdBind (register an internal client as a tunnel connector).
func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &tunnelHandler{
		options: options,
	}
}

// Init initializes the tunnel handler.
//
// It parses metadata, generates a unique node ID, creates the connector pool,
// starts all configured entrypoint services, sets up observer stats with a
// background goroutine, and initializes the traffic limiter.
func (h *tunnelHandler) Init(md md.Metadata) (err error) {
	if err := h.parseMetadata(md); err != nil {
		return err
	}

	uuid, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	h.id = uuid.String()

	h.log = h.options.Logger.WithFields(map[string]any{
		"node": h.id,
	})
	h.pool = NewConnectorPool(h.id)

	if err = h.initEntrypoints(); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel

	if h.options.Observer != nil {
		h.stats = stats_util.NewHandlerStats(h.options.Service, h.md.observerResetTraffic)
		go h.observeStats(ctx)
	}

	if h.options.Limiter != nil {
		h.limiter = cache_limiter.NewCachedTrafficLimiter(h.options.Limiter,
			cache_limiter.RefreshIntervalOption(h.md.limiterRefreshInterval),
			cache_limiter.CleanupIntervalOption(h.md.limiterCleanupInterval),
			cache_limiter.ScopeOption(limiter.ScopeClient),
		)
	}

	return nil
}

// Handle processes an incoming relay-protocol connection.
//
// The connection is expected to start with a relay.Request frame. The handler
// parses the request, extracts authentication, addresses, network type, and
// tunnel ID, then dispatches to handleConnect (CmdConnect) or handleBind
// (CmdBind).
//
// Rate limiting is checked before reading the request. A read deadline is
// applied during the initial relay frame read and cleared afterwards.
//
// On error, a relay.Response with the appropriate error status is written
// before returning. The caller is responsible for closing conn on success
// (the CmdConnect path defers conn.Close() internally).
func (h *tunnelHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	start := time.Now()

	var clientAddr string
	if srcAddr := xctx.SrcAddrFromContext(ctx); srcAddr != nil {
		clientAddr = srcAddr.String()
	}

	log := h.log.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"client": clientAddr,
		"sid":    xctx.SidFromContext(ctx).String(),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())

	defer func() {
		if err != nil {
			conn.Close()
		}
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return rate_limiter.ErrRateLimit
	}

	if h.md.readTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(h.md.readTimeout))
	}

	req := relay.Request{}
	if _, err := req.ReadFrom(conn); err != nil {
		return err
	}

	conn.SetReadDeadline(time.Time{})

	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	if req.Version != relay.Version1 {
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn) // write error ignored — conn is about to be closed
		return ErrBadVersion
	}

	var user, pass string
	var srcAddr, dstAddr string
	network := "tcp"
	var tunnelID relay.TunnelID
	for _, f := range req.Features {
		switch f.Type() {
		case relay.FeatureUserAuth:
			if feature, _ := f.(*relay.UserAuthFeature); feature != nil {
				user, pass = feature.Username, feature.Password
			}
		case relay.FeatureAddr:
			if feature, _ := f.(*relay.AddrFeature); feature != nil {
				v := net.JoinHostPort(feature.Host, strconv.Itoa(int(feature.Port)))
				if srcAddr != "" {
					dstAddr = v
				} else {
					srcAddr = v
				}
			}
		case relay.FeatureTunnel:
			if feature, _ := f.(*relay.TunnelFeature); feature != nil {
				tunnelID = feature.ID
			}
		case relay.FeatureNetwork:
			if feature, _ := f.(*relay.NetworkFeature); feature != nil {
				network = feature.Network.String()
			}
		}
	}

	if tunnelID.IsZero() {
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn) // write error ignored — conn is about to be closed
		return ErrTunnelID
	}

	if user != "" {
		log = log.WithFields(map[string]any{"user": user})
	}

	if h.options.Auther != nil {
		clientID, ok := h.options.Auther.Authenticate(ctx, user, pass, auth.WithService(h.options.Service))
		if !ok {
			resp.Status = relay.StatusUnauthorized
			resp.WriteTo(conn) // write error ignored — conn is about to be closed
			return ErrUnauthorized
		}
		ctx = xctx.ContextWithClientID(ctx, xctx.ClientID(clientID))
	}

	switch req.Cmd & relay.CmdMask {
	case relay.CmdConnect:
		defer conn.Close()

		log.Debugf("connect: %s >> %s/%s", srcAddr, dstAddr, network)
		return h.handleConnect(ctx, &req, conn, network, srcAddr, dstAddr, tunnelID, log)

	case relay.CmdBind:
		log.Debugf("bind: %s >> %s/%s", srcAddr, dstAddr, network)
		return h.handleBind(ctx, conn, network, dstAddr, tunnelID, log)
	default:
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn) // write error ignored — conn is about to be closed
		return ErrUnknownCmd
	}
}

// Close implements io.Closer.
//
// It closes all entrypoint services, the connector pool (which closes all
// tunnels and connectors), and cancels the observer stats goroutine.
func (h *tunnelHandler) Close() error {
	for _, ep := range h.entrypoints {
		ep.Close()
	}
	h.pool.Close()

	if h.cancel != nil {
		h.cancel()
	}

	return nil
}

// checkRateLimit returns false if the connection source IP exceeds the
// configured rate limiter budget. Returns true if no rate limiter is set.
func (h *tunnelHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}

// observeStats is a background goroutine that periodically flushes connection
// stats events to the configured observer.
//
// On observe failure, events are buffered and retried on the next tick.
// On retry success, new events from the current tick are also flushed
// (fall-through via the pending-events block). On persistent failure,
// new events are skipped until the pending batch is accepted.
func (h *tunnelHandler) observeStats(ctx context.Context) {
	if h.options.Observer == nil {
		return
	}

	var events []observer.Event

	ticker := time.NewTicker(h.md.observerPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Try to flush any buffered events from a previous failed attempt.
			if len(events) > 0 {
				if err := h.options.Observer.Observe(ctx, events); err != nil {
					continue
				}
			}

			// Collect and send fresh events.
			if evs := h.stats.Events(); len(evs) > 0 {
				if err := h.options.Observer.Observe(ctx, evs); err != nil {
					events = evs
					continue
				}
			}
			events = nil

		case <-ctx.Done():
			return
		}
	}
}
