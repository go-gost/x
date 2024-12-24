package sni

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/go-gost/core/handler"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/sniffing"
	tls_util "github.com/go-gost/x/internal/util/tls"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("sni", NewHandler)
}

type sniHandler struct {
	md       metadata
	options  handler.Options
	recorder recorder.RecorderObject
	certPool tls_util.CertPool
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	h := &sniHandler{
		options: options,
	}

	return h
}

func (h *sniHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
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

func (h *sniHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Network:    "tcp",
		Time:       start,
		SID:        string(ctxvalue.SidFromContext(ctx)),
	}

	ro.ClientIP = conn.RemoteAddr().String()
	if clientAddr := ctxvalue.ClientAddrFromContext(ctx); clientAddr != "" {
		ro.ClientIP = string(clientAddr)
	}
	if h, _, _ := net.SplitHostPort(ro.ClientIP); h != "" {
		ro.ClientIP = h
	}

	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
		"client": ro.ClientIP,
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

	br := bufio.NewReader(conn)
	proto, _ := sniffing.Sniff(ctx, br)
	ro.Proto = proto

	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		var buf bytes.Buffer
		cc, err := h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &buf), "tcp", address)
		ro.Route = buf.String()
		return cc, err
	}
	dialTLS := func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
		var buf bytes.Buffer
		cc, err := h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &buf), "tcp", address)
		ro.Route = buf.String()
		if err != nil {
			return nil, err
		}
		cc = tls.Client(cc, cfg)
		return cc, nil
	}

	sniffer := &sniffing.Sniffer{
		Websocket:           h.md.sniffingWebsocket,
		WebsocketSampleRate: h.md.sniffingWebsocketSampleRate,
		Recorder:            h.recorder.Recorder,
		RecorderOptions:     h.recorder.Options,
		Certificate:         h.md.certificate,
		PrivateKey:          h.md.privateKey,
		NegotiatedProtocol:  h.md.alpn,
		CertPool:            h.certPool,
		MitmBypass:          h.md.mitmBypass,
		ReadTimeout:         h.md.readTimeout,
	}
	conn = xnet.NewReadWriteConn(br, conn, conn)
	switch proto {
	case sniffing.ProtoHTTP:
		return sniffer.HandleHTTP(ctx, conn,
			sniffing.WithDial(dial),
			sniffing.WithDialTLS(dialTLS),
			sniffing.WithBypass(h.options.Bypass),
			sniffing.WithRecorderObject(ro),
			sniffing.WithLog(log),
		)
	case sniffing.ProtoTLS:
		return sniffer.HandleTLS(ctx, conn,
			sniffing.WithDial(dial),
			sniffing.WithDialTLS(dialTLS),
			sniffing.WithBypass(h.options.Bypass),
			sniffing.WithRecorderObject(ro),
			sniffing.WithLog(log),
		)
	default:
		return errors.New("unknown traffic")
	}
}

func (h *sniHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}
