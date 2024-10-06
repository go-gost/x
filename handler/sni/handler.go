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
	"github.com/go-gost/core/recorder"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/sniffing"
	tls_util "github.com/go-gost/x/internal/util/tls"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

const (
	defaultBodySize = 1024 * 1024 // 1MB
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
	ro.ClientIP, _, _ = net.SplitHostPort(conn.RemoteAddr().String())

	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		if err := ro.AddTrafficField(conn); err != nil {
			log.Errorf("error adding traffic field: %s", err)
		}
		if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return rate_limiter.ErrRateLimit
	}

	br := bufio.NewReader(conn)
	proto, _ := sniffing.Sniff(ctx, br)
	ro.Proto = proto

	sniffer := &sniffing.Sniffer{
		Recorder:           h.recorder.Recorder,
		RecorderOptions:    h.recorder.Options,
		RecorderObject:     ro,
		Certificate:        h.md.certificate,
		PrivateKey:         h.md.privateKey,
		NegotiatedProtocol: h.md.alpn,
		CertPool:           h.certPool,
		MitmBypass:         h.md.mitmBypass,
		ReadTimeout:        h.md.readTimeout,
		Log:                log,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var buf bytes.Buffer
			cc, err := h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &buf), "tcp", address)
			ro.Route = buf.String()
			return cc, err
		},
		DialTLS: func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
			var buf bytes.Buffer
			cc, err := h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &buf), "tcp", address)
			ro.Route = buf.String()
			if err != nil {
				return nil, err
			}
			cc = tls.Client(cc, cfg)
			return cc, nil
		},
	}
	conn = xnet.NewReadWriteConn(br, conn, conn)
	switch proto {
	case sniffing.ProtoHTTP:
		return sniffer.HandleHTTP(ctx, conn)
	case sniffing.ProtoTLS:
		return sniffer.HandleTLS(ctx, conn)
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
