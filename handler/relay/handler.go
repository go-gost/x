package relay

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/relay"
	xctx "github.com/go-gost/x/ctx"
	stats_util "github.com/go-gost/x/internal/util/stats"
	tls_util "github.com/go-gost/x/internal/util/tls"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	cache_limiter "github.com/go-gost/x/limiter/traffic/cache"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

var (
	ErrBadVersion   = errors.New("relay: bad version")
	ErrUnknownCmd   = errors.New("relay: unknown command")
	ErrUnauthorized = errors.New("relay: unauthorized")
)

func init() {
	registry.HandlerRegistry().Register("relay", NewHandler)
}

// relayHandler is the GOST relay protocol server handler.
//
// The GOST relay protocol is a custom multiplexed transport supporting three modes:
//  1. Connect — the client requests a connection to a target address.
//     The handler dials via the configured Router and pipes data bidirectionally.
//     - Direct: handleConnect(), target address from the relay request.
//     - Forward: handleForward(), target from hop selector (load balancing).
//  2. Bind — the client asks the handler to listen on a local port and forward
//     incoming connections back through a mux session. Used for reverse proxying.
//  3. Forward — when a hop is set, the target is selected by the hop's strategy
//     rather than specified by the client.
//
// Data flow:
//
//	┌─────────────────────────────────────────────────────────┐
//	│ Handle() → parse relay.Request                          │
//	│   ├─ extract auth (UserAuthFeature) → authenticate      │
//	│   ├─ extract target address (AddrFeature)                │
//	│   └─ extract network type (NetworkFeature)               │
//	│                                                          │
//	│ ┌── hop set? ──→ handleForward()                         │
//	│ │   ├─ hop.Select() pick target node                     │
//	│ │   └─ Router.Dial() → Pipe bidir copy                   │
//	│                                                          │
//	│ └── no hop, dispatch by command:                         │
//	│   ├─ CmdConnect → handleConnect()                        │
//	│   │   ├─ bypass check                                    │
//	│   │   ├─ consistent-hashing                              │
//	│   │   ├─ Router.Dial() / net.Dial() / serial.Open        │
//	│   │   ├─ send response header (noDelay)                  │
//	│   │   ├─ optional protocol sniffing (HTTP/TLS MITM)      │
//	│   │   └─ Pipe bidir data copy                            │
//	│   └─ CmdBind → handleBind()                              │
//	│       ├─ bindTCP: net.Listen → mux session → tcpHandler │
//	│       └─ bindUDP: net.ListenPacket → udp.Relay           │
//	└─────────────────────────────────────────────────────────┘
type relayHandler struct {
	hop      hop.Hop
	md       metadata
	options  handler.Options
	stats    *stats_util.HandlerStats
	limiter  traffic.TrafficLimiter
	cancel   context.CancelFunc
	recorder recorder.RecorderObject
	certPool tls_util.CertPool
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &relayHandler{
		options: options,
	}
}

// Init initialises the relay handler. Called after the handler is registered with a service.
//
// Initialisation flow:
//  1. Parse metadata config (timeouts, sniffing, mux, MITM, etc.)
//  2. If an Observer is configured, create a stats counter and start the background polling goroutine.
//  3. If a TrafficLimiter is configured, create a cached traffic limiter.
//  4. Pick the ServiceHandler recorder from the recorder list.
//  5. If MITM certificates are configured, create an in-memory cert pool.
func (h *relayHandler) Init(md md.Metadata) (err error) {
	if err := h.parseMetadata(md); err != nil {
		return err
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

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandler {
			h.recorder = ro
			break
		}
	}

	if h.md.certificate != nil && h.md.privateKey != nil {
		h.certPool = tls_util.NewMemoryCertPool()
	}

	return nil
}

// Forward implements handler.Forwarder.
func (h *relayHandler) Forward(hop hop.Hop) {
	h.hop = hop
}

// Handle is the main entry point for each inbound connection.
//
// Flow:
//  1. Create a recorder object with connection metadata.
//  2. Wrap the connection for stats collection (input/output bytes).
//  3. Rate-limit check.
//  4. Set read deadline, read the relay.Request.
//  5. Clear the read deadline.
//  6. Check the relay protocol version.
//  7. Parse request features (auth, address, network type).
//  8. Authenticate (if an Auther is configured).
//  9. Dispatch:
//     - If hop is set → handleForward.
//     - CmdConnect → handleConnect.
//     - CmdBind → handleBind.
//  10. Deferred final stats recording.
func (h *relayHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Network:    "tcp",
		Service:    h.options.Service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		SID:        xctx.SidFromContext(ctx).String(),
		Time:       start,
	}

	if srcAddr := xctx.SrcAddrFromContext(ctx); srcAddr != nil {
		ro.ClientAddr = srcAddr.String()
	}

	log := h.options.Logger.WithFields(map[string]any{
		"network": ro.Network,
		"remote":  conn.RemoteAddr().String(),
		"local":   conn.LocalAddr().String(),
		"client":  ro.ClientAddr,
		"sid":     ro.SID,
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(start)
		if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(start),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
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
		resp.WriteTo(conn)
		return ErrBadVersion
	}

	var user, pass string
	var address string
	var addrFeature *relay.AddrFeature
	var networkID relay.NetworkID
	for _, f := range req.Features {
		switch f.Type() {
		case relay.FeatureUserAuth:
			if feature, _ := f.(*relay.UserAuthFeature); feature != nil {
				user, pass = feature.Username, feature.Password
			}
		case relay.FeatureAddr:
			if feature, _ := f.(*relay.AddrFeature); feature != nil {
				addrFeature = feature
			}
		case relay.FeatureNetwork:
			if feature, _ := f.(*relay.NetworkFeature); feature != nil {
				networkID = feature.Network
			}
		}
	}

	if user != "" {
		ro.ClientID = user
		log = log.WithFields(map[string]any{"user": user})
	}

	if h.options.Auther != nil {
		clientID, ok := h.options.Auther.Authenticate(ctx, user, pass, auth.WithService(h.options.Service))
		if !ok {
			resp.Status = relay.StatusUnauthorized
			resp.WriteTo(conn)
			return ErrUnauthorized
		}
		log = log.WithFields(map[string]any{"clientID": clientID})
		ro.ClientID = clientID
		ctx = xctx.ContextWithClientID(ctx, xctx.ClientID(clientID))
	}

	network := networkID.String()
	if (req.Cmd & relay.FUDP) == relay.FUDP {
		network = "udp"
	}
	if addrFeature != nil {
		switch network {
		case "unix", "serial":
			address = addrFeature.Host
		default:
			address = net.JoinHostPort(addrFeature.Host, strconv.Itoa(int(addrFeature.Port)))
		}
	}
	ro.Network = network
	ro.Host = address
	log = log.WithFields(map[string]any{"network": network})

	if h.hop != nil {
		// Forward mode: target is selected from the hop.
		return h.handleForward(ctx, conn, network, ro, log)
	}

	switch req.Cmd & relay.CmdMask {
	case 0, relay.CmdConnect:
		return h.handleConnect(ctx, conn, network, address, ro, log)
	case relay.CmdBind:
		return h.handleBind(ctx, conn, network, address, ro, log)
	default:
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		return ErrUnknownCmd
	}
}

// Close implements io.Closer interface.
func (h *relayHandler) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	return nil
}
