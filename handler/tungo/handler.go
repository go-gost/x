package tungo

import (
	"context"
	"errors"
	"net"
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
	tun_util "github.com/go-gost/x/internal/util/tun"
	cache_limiter "github.com/go-gost/x/limiter/traffic/cache"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/option"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func init() {
	registry.HandlerRegistry().Register("tungo", NewHandler)
}

type tungoHandler struct {
	options  handler.Options
	md       metadata
	stats    *stats_util.HandlerStats
	limiter  traffic.TrafficLimiter
	cancel   context.CancelFunc
	recorder recorder.RecorderObject
	stack    *stack.Stack
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &tungoHandler{
		options: options,
	}
}

func (h *tungoHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
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

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandler {
			h.recorder = ro
			break
		}
	}

	return
}

func (h *tungoHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	log := h.options.Logger

	var config *tun_util.Config
	if md := ictx.MetadataFromContext(ctx); md != nil {
		config, _ = md.Get("config").(*tun_util.Config)
	}
	if config == nil {
		err := errors.New("tun: wrong connection type")
		log.Error(err)
		return err
	}

	start := time.Now()
	log = log.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    xctx.SidFromContext(ctx).String(),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	th := &transportHandler{
		service: h.options.Service,

		tcpQueue:   make(chan adapter.TCPConn),
		udpQueue:   make(chan adapter.UDPConn),
		udpTimeout: h.md.udpTimeout,
		procCancel: func() {},

		sniffing:                h.md.sniffing,
		sniffingUDP:             h.md.sniffingUDP,
		sniffingTimeout:         h.md.sniffingTimeout,
		sniffingResponseTimeout: h.md.sniffingResponseTimeout,
		sniffingFallback:        h.md.sniffingFallback,

		recorder: h.recorder,
		stats:    h.stats,

		ipv6: h.md.ipv6,

		opts: &h.options,
	}

	th.ProcessAsync()
	defer th.Close()

	var cOpts []option.Option
	if h.md.tcpModerateReceiveBuffer {
		cOpts = append(cOpts, option.WithTCPModerateReceiveBuffer(h.md.tcpModerateReceiveBuffer))
	}
	if h.md.tcpSendBufferSize > 0 {
		cOpts = append(cOpts, option.WithTCPSendBufferSize(h.md.tcpSendBufferSize))
	}
	if h.md.tcpReceiveBufferSize > 0 {
		cOpts = append(cOpts, option.WithTCPReceiveBufferSize(h.md.tcpReceiveBufferSize))
	}

	stack, err := core.CreateStack(&core.Config{
		LinkEndpoint:     newEndpoint(conn, config.MTU, log),
		TransportHandler: th,
		MulticastGroups:  h.md.multicastGroups,
		Options:          cOpts,
	})
	if err != nil {
		return err
	}

	h.stack = stack

	stack.Wait()

	return nil
}

// Close implements io.Closer interface.
func (h *tungoHandler) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	if h.stack != nil {
		h.stack.Close()
	}
	return nil
}

func (h *tungoHandler) observeStats(ctx context.Context) {
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
