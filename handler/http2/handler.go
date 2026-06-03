// Package http2 implements an HTTP/2 proxy handler. It supports both forward
// proxy (GET/POST/CONNECT) and tunnel modes with optional probe resistance,
// bypass, traffic limiting, and observability.
//
// The handler is registered under the name "http2" and created via
// NewHandler in init(). It is designed for use with HTTP/2 (h2/h2c) listeners.
//
// # Request processing flow
//
// Each inbound net.Conn is handled by Handle, which delegates to roundTrip
// for authentication, bypass checks, routing, and forwarding.
//
//	Handle()
//	  ├─ checkRateLimit (connection rate limiter, if configured)
//	  ├─ ictx.MetadataFromContext (extract w, r from HTTP/2 stream context)
//	  └─ roundTrip()
//	    ├─ decodeServerName (GOST 2.x compatibility headers)
//	    ├─ authenticate (basic proxy auth + probe resistance)
//	    ├─ bypass check
//	    ├─ set metadata response headers
//	    ├─ Router.Dial (connect to upstream)
//	    ├─ forwardRequest (non-CONNECT: wrap with traffic limiter + stats, proxy request + error response on failure)
//	    └─ CONNECT tunnel (bi-directional pipe with idle timeout)
package http2

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	stats_util "github.com/go-gost/x/internal/util/stats"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	cache_limiter "github.com/go-gost/x/limiter/traffic/cache"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

// Sentinel errors returned by the HTTP/2 handler.
var (
	ErrAuthFailed    = errors.New("http2: authentication failed")
	ErrWrongConnType = errors.New("http2: wrong connection type")
)

func init() {
	registry.HandlerRegistry().Register("http2", NewHandler)
}

type http2Handler struct {
	md       metadata
	options  handler.Options
	stats    *stats_util.HandlerStats
	limiter  traffic.TrafficLimiter
	cancel   context.CancelFunc
	recorder recorder.RecorderObject
}

// NewHandler creates a new HTTP/2 proxy handler. It supports forward proxy
// (GET/POST/CONNECT) and tunnel modes with optional probe resistance, bypass,
// traffic limiting, and observability. The handler is registered under the
// name "http2" and is intended for use with HTTP/2 (h2/h2c) listeners.
func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &http2Handler{
		options: options,
	}
}

func (h *http2Handler) Init(md md.Metadata) error {
	h.parseMetadata(md)

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

	return nil
}

func (h *http2Handler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Network:    "tcp",
		Time:       start,
		SID:        xctx.SidFromContext(ctx).String(),
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
	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.Duration = time.Since(start)
		ro.Record(ctx, h.recorder.Recorder)

		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return rate_limiter.ErrRateLimit
	}

	md := ictx.MetadataFromContext(ctx)
	if md == nil {
		err = ErrWrongConnType
		log.Error(err)
		return err
	}

	w, _ := md.Get("w").(http.ResponseWriter)
	r, _ := md.Get("r").(*http.Request)

	return h.roundTrip(ctx, w, r, ro, log)
}

func (h *http2Handler) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	return nil
}

func (h *http2Handler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}

func (h *http2Handler) observeStats(ctx context.Context) {
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
