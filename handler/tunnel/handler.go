package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/service"
	"github.com/go-gost/relay"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	stats_util "github.com/go-gost/x/internal/util/stats"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	cache_limiter "github.com/go-gost/x/limiter/traffic/cache"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
	xservice "github.com/go-gost/x/service"
	"github.com/google/uuid"
)

var (
	ErrBadVersion         = errors.New("bad version")
	ErrUnknownCmd         = errors.New("unknown command")
	ErrTunnelID           = errors.New("invalid tunnel ID")
	ErrTunnelNotAvailable = errors.New("tunnel not available")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrTunnelRoute        = errors.New("no route to host")
	ErrPrivateTunnel      = errors.New("private tunnel")
)

func init() {
	registry.HandlerRegistry().Register("tunnel", NewHandler)
}

type tunnelHandler struct {
	id      string
	options handler.Options
	pool    *ConnectorPool
	epSvc   service.Service
	ep      *entrypoint
	md      metadata
	log     logger.Logger
	stats   *stats_util.HandlerStats
	limiter traffic.TrafficLimiter
	cancel  context.CancelFunc
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &tunnelHandler{
		options: options,
	}
}

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

	h.ep = &entrypoint{
		node:    h.id,
		service: h.options.Service,
		pool:    h.pool,
		ingress: h.md.ingress,
		sd:      h.md.sd,
		log: h.log.WithFields(map[string]any{
			"kind": "entrypoint",
		}),
		sniffingWebsocket:   h.md.sniffingWebsocket,
		websocketSampleRate: h.md.sniffingWebsocketSampleRate,
		readTimeout:         h.md.entryPointReadTimeout,
	}
	h.ep.transport = &http.Transport{
		DialContext:           h.ep.dial,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: h.md.entryPointReadTimeout,
		DisableKeepAlives:     !h.md.entryPointKeepalive,
		DisableCompression:    !h.md.entryPointCompression,
	}

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandler {
			h.ep.recorder = ro
			break
		}
	}
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

func (h *tunnelHandler) initEntrypoint() (err error) {
	if h.md.entryPoint == "" {
		return
	}

	network := "tcp"
	if xnet.IsIPv4(h.md.entryPoint) {
		network = "tcp4"
	}

	ln, err := net.Listen(network, h.md.entryPoint)
	if err != nil {
		h.log.Error(err)
		return
	}

	serviceName := fmt.Sprintf("%s-ep-%s", h.options.Service, ln.Addr())
	log := h.log.WithFields(map[string]any{
		"service":  serviceName,
		"listener": "tcp",
		"handler":  "tunnel-ep",
		"kind":     "service",
	})
	epListener := newTCPListener(ln,
		listener.AddrOption(h.md.entryPoint),
		listener.ServiceOption(serviceName),
		listener.ProxyProtocolOption(h.md.entryPointProxyProtocol),
		listener.LoggerOption(log.WithFields(map[string]any{
			"kind": "listener",
		})),
	)
	if err = epListener.Init(nil); err != nil {
		return
	}
	epHandler := &entrypointHandler{
		ep: h.ep,
	}
	if err = epHandler.Init(nil); err != nil {
		return
	}

	h.epSvc = xservice.NewService(
		serviceName, epListener, epHandler,
		xservice.LoggerOption(log),
	)
	go h.epSvc.Serve()
	log.Infof("entrypoint: %s", h.epSvc.Addr())

	return
}

func (h *tunnelHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	start := time.Now()
	log := h.log.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
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
		resp.WriteTo(conn)
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
		resp.WriteTo(conn)
		return ErrTunnelID
	}

	if user != "" {
		log = log.WithFields(map[string]any{"user": user})
	}

	if h.options.Auther != nil {
		clientID, ok := h.options.Auther.Authenticate(ctx, user, pass)
		if !ok {
			resp.Status = relay.StatusUnauthorized
			resp.WriteTo(conn)
			return ErrUnauthorized
		}
		ctx = ctxvalue.ContextWithClientID(ctx, ctxvalue.ClientID(clientID))
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
		resp.WriteTo(conn)
		return ErrUnknownCmd
	}
}

// Close implements io.Closer interface.
func (h *tunnelHandler) Close() error {
	if h.epSvc != nil {
		h.epSvc.Close()
	}
	h.pool.Close()

	if h.cancel != nil {
		h.cancel()
	}

	return nil
}

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
			if len(events) > 0 {
				if err := h.options.Observer.Observe(ctx, events); err == nil {
					events = nil
				}
				break
			}

			evs := h.stats.Events()
			if err := h.options.Observer.Observe(ctx, evs); err != nil {
				events = evs
			}

		case <-ctx.Done():
			return
		}
	}
}
