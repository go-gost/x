package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/relay"
	xctx "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/cache"
	stats_util "github.com/go-gost/x/internal/util/stats"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	cache_limiter "github.com/go-gost/x/limiter/traffic/cache"
	"github.com/go-gost/x/registry"
	"github.com/google/uuid"
)

// Error sentinel values returned by the router handler.
var (
	ErrBadVersion   = errors.New("bad version")
	ErrUnknownCmd   = errors.New("unknown command")
	ErrRouterID     = errors.New("invalid router ID")
	ErrUnauthorized = errors.New("unauthorized")
)

func init() {
	registry.HandlerRegistry().Register("router", NewHandler)
}

// routerHandler is the main handler for the GOST relay router protocol.
//
// It acts as the server-side component of a tunnel mesh: accepts TCP
// connections from client nodes, authenticates them, and routes IP
// packets between the mesh participants.
//
// # Architecture
//
//	┌───────────────┐
//	│  routerHandler │
//	├───────────────┤
//	│ pool          │ ── ConnectorPool: manages all active connectors
//	│ epConn        │ ── UDP packet conn for inter-node forwarding
//	│ sdCache       │ ── Cache for service discovery lookups
//	│ routeCache    │ ── Cache for route lookups
//	│ stats         │ ── Per-connector traffic statistics
//	│ limiter       │ ── Traffic rate limiter (per-client)
//	└───────────────┘
//
// The handler only supports relay.CmdAssociate (IP packet forwarding).
// Other commands return ErrUnknownCmd.
type routerHandler struct {
	id         string
	options    handler.Options
	pool       *ConnectorPool
	epConn     net.PacketConn       // UDP socket for inter-node packet forwarding
	md         metadata
	log        logger.Logger
	stats      *stats_util.HandlerStats
	limiter    traffic.TrafficLimiter
	cancel     context.CancelFunc   // cancels background goroutines (observeStats)
	sdCache    *cache.Cache         // service discovery address cache
	routeCache *cache.Cache         // route lookup cache
}

// NewHandler creates a new router handler.
//
// Caches are initialized with a 1-minute default TTL; individual entries
// may override this via metadata configuration.
func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &routerHandler{
		options:    options,
		sdCache:    cache.NewCache(time.Minute),
		routeCache: cache.NewCache(time.Minute),
	}
}

// Init initializes the handler with the given metadata.
//
// Initialization sequence:
//  1. Parse metadata (read timeout, buffer size, entrypoint, etc.)
//  2. Generate a random node ID (UUID)
//  3. Create the connector pool
//  4. Initialize the UDP entrypoint listener (if configured)
//  5. Start the observer stats goroutine (if an observer is set)
//  6. Initialize the traffic limiter (if configured)
func (h *routerHandler) Init(md md.Metadata) (err error) {
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

	if err = h.initEntrypoint(); err != nil {
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

// initEntrypoint creates the UDP listening socket for inter-node
// packet forwarding and starts the background read loop.
//
// The entrypoint is optional — if no entrypoint address is configured,
// this node cannot receive packets from other mesh nodes (it can only
// forward packets to connectors that were established via TCP).
func (h *routerHandler) initEntrypoint() (err error) {
	if h.md.entryPoint == "" {
		return
	}

	network := "udp"
	if xnet.IsIPv4(h.md.entryPoint) {
		network = "udp4"
	}

	pc, err := net.ListenPacket(network, h.md.entryPoint)
	if err != nil {
		h.log.Error(err)
		return
	}
	h.epConn = pc

	log := h.log.WithFields(map[string]any{
		"service":  fmt.Sprintf("%s-ep-%s", h.options.Service, pc.LocalAddr()),
		"listener": "udp",
		"handler":  "entrypoint",
		"kind":     "service",
	})
	go h.handleEntrypoint(log)
	h.log.Infof("entrypoint: %s", pc.LocalAddr())

	return
}

// Handle processes an incoming TCP connection using the relay protocol.
//
// # Protocol flow
//
//  1. Read the relay request from the client (with optional read timeout).
//  2. Validate the protocol version.
//  3. Parse features: user authentication, addresses, tunnel ID, network.
//  4. Authenticate the client (if an auther is configured).
//  5. Dispatch to handleAssociate for CmdAssociate, or reject with error.
//
// The connection is always closed on return (via defer).
//
// # Feature parsing order
//
// The relay protocol allows multiple AddrFeatures. The first AddrFeature
// is treated as the source address, the second as the destination. This
// mirrors the behavior of other relay-based handlers (e.g., handler/relay).
func (h *routerHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()
	log := h.log.WithFields(map[string]any{
		"network": conn.LocalAddr().Network(),
		"remote":  conn.RemoteAddr().String(),
		"local":   conn.LocalAddr().String(),
		"sid":     xctx.SidFromContext(ctx).String(),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())

	defer func() {
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

	// Clear the read deadline — subsequent data transfer (IP packets
	// through the packetConn) should not be time-limited.
	conn.SetReadDeadline(time.Time{})

	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	if req.Version != relay.Version1 {
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		return ErrBadVersion
	}

	var user, pass string
	var srcAddr, dstAddr string
	network := "ip"
	var routerID relay.TunnelID
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
				routerID = feature.ID
			}
		case relay.FeatureNetwork:
			if feature, _ := f.(*relay.NetworkFeature); feature != nil {
				network = feature.Network.String()
			}
		}
	}

	if user != "" {
		log = log.WithFields(map[string]any{"user": user})
	}

	// Authenticate before establishing the tunnel association.
	if h.options.Auther != nil {
		clientID, ok := h.options.Auther.Authenticate(ctx, user, pass, auth.WithService(h.options.Service))
		if !ok {
			resp.Status = relay.StatusUnauthorized
			resp.WriteTo(conn)
			return ErrUnauthorized
		}
		ctx = xctx.ContextWithClientID(ctx, xctx.ClientID(clientID))
	}

	switch req.Cmd & relay.CmdMask {
	case relay.CmdAssociate:
		host, _, _ := net.SplitHostPort(dstAddr)
		log.Debugf("associate %s/%s -> %s", host, network, routerID)
		return h.handleAssociate(ctx, conn, network, host, routerID, log)

	default:
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		return ErrUnknownCmd
	}
}

// Close shuts down the handler: closes the entrypoint UDP socket,
// closes the connector pool (which closes all connectors), and
// cancels background goroutines.
//
// Implements io.Closer.
func (h *routerHandler) Close() error {
	if h.epConn != nil {
		h.epConn.Close()
	}
	h.pool.Close()

	if h.cancel != nil {
		h.cancel()
	}

	return nil
}
