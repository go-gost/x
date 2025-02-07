package router

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/service"
	"github.com/go-gost/relay"
	ctxvalue "github.com/go-gost/x/ctx"
	limiter_util "github.com/go-gost/x/internal/util/limiter"
	stats_util "github.com/go-gost/x/internal/util/stats"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	"github.com/go-gost/x/registry"
	"github.com/google/uuid"
)

var (
	ErrBadVersion         = errors.New("bad version")
	ErrUnknownCmd         = errors.New("unknown command")
	ErrRouterID           = errors.New("invalid router ID")
	ErrRouterNotAvailable = errors.New("router not available")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrTunnelRoute        = errors.New("no route to host")
)

func init() {
	registry.HandlerRegistry().Register("router", NewHandler)
}

type routerHandler struct {
	id      string
	options handler.Options
	pool    *ConnectorPool
	epSvc   service.Service
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

	return &routerHandler{
		options: options,
	}
}

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

	/*
		for _, ro := range h.options.Recorders {
			if ro.Record == xrecorder.RecorderServiceHandler {
				h.ep.recorder = ro
				break
			}
		}
	*/

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel

	if h.options.Observer != nil {
		h.stats = stats_util.NewHandlerStats(h.options.Service, h.md.observerResetTraffic)
		go h.observeStats(ctx)
	}

	if h.options.Limiter != nil {
		h.limiter = limiter_util.NewCachedTrafficLimiter(h.options.Limiter,
			limiter_util.RefreshIntervalOption(h.md.limiterRefreshInterval),
			limiter_util.CleanupIntervalOption(h.md.limiterCleanupInterval),
			limiter_util.ScopeOption(limiter.ScopeClient),
		)
	}

	return nil
}

func (h *routerHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()
	log := h.log.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
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

	if routerID.IsZero() {
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		return ErrRouterID
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

// Close implements io.Closer interface.
func (h *routerHandler) Close() error {
	if h.epSvc != nil {
		h.epSvc.Close()
	}
	h.pool.Close()

	if h.cancel != nil {
		h.cancel()
	}

	return nil
}

func (h *routerHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}

func (h *routerHandler) observeStats(ctx context.Context) {
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
