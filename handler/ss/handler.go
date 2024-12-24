package ss

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/handler"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/gosocks5"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/sniffing"
	"github.com/go-gost/x/internal/util/ss"
	tls_util "github.com/go-gost/x/internal/util/tls"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

func init() {
	registry.HandlerRegistry().Register("ss", NewHandler)
}

type ssHandler struct {
	cipher   core.Cipher
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

	return &ssHandler{
		options: options,
	}
}

func (h *ssHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}
	if h.options.Auth != nil {
		method := h.options.Auth.Username()
		password, _ := h.options.Auth.Password()
		h.cipher, err = ss.ShadowCipher(method, password, h.md.key)
		if err != nil {
			return
		}
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

	return
}

func (h *ssHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		Network:    "tcp",
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
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

	if h.cipher != nil {
		conn = ss.ShadowConn(h.cipher.StreamConn(conn), nil)
	}

	conn.SetReadDeadline(time.Now().Add(h.md.readTimeout))

	addr := &gosocks5.Addr{}
	if _, err := addr.ReadFrom(conn); err != nil {
		log.Error(err)
		io.Copy(io.Discard, conn)
		return err
	}
	ro.Host = addr.String()

	conn.SetReadDeadline(time.Time{})

	log = log.WithFields(map[string]any{
		"dst":  addr.String(),
		"host": addr.String(),
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), addr)

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, "tcp", addr.String()) {
		log.Debug("bypass: ", addr.String())
		return nil
	}

	switch h.md.hash {
	case "host":
		ctx = ctxvalue.ContextWithHash(ctx, &ctxvalue.Hash{Source: addr.String()})
	}

	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &buf), "tcp", addr.String())
	ro.Route = buf.String()
	if err != nil {
		return err
	}
	defer cc.Close()

	if h.md.sniffing {
		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(h.md.sniffingTimeout))
		}

		br := bufio.NewReader(conn)
		proto, _ := sniffing.Sniff(ctx, br)
		ro.Proto = proto

		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Time{})
		}

		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			return cc, nil
		}
		dialTLS := func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
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
				sniffing.WithRecorderObject(ro),
				sniffing.WithLog(log),
			)
		case sniffing.ProtoTLS:
			return sniffer.HandleTLS(ctx, conn,
				sniffing.WithDial(dial),
				sniffing.WithDialTLS(dialTLS),
				sniffing.WithRecorderObject(ro),
				sniffing.WithLog(log),
			)
		}
	}

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), ro.Host)
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), ro.Host)

	return nil
}

func (h *ssHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}
