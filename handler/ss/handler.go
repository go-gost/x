package ss

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/handler"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/gosocks5"
	ctxvalue "github.com/go-gost/x/ctx"
	netpkg "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/ss"
	rate_limiter "github.com/go-gost/x/limiter/rate"
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
	ro.ClientIP, _, _ = net.SplitHostPort(conn.RemoteAddr().String())

	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		if !ro.Time.IsZero() {
			if err != nil {
				ro.Err = err.Error()
			}
			ro.Duration = time.Since(start)
			ro.Record(ctx, h.recorder.Recorder)
		}

		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return rate_limiter.ErrRateLimit
	}

	if h.cipher != nil {
		conn = ss.ShadowConn(h.cipher.StreamConn(conn), nil)
	}

	if h.md.readTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(h.md.readTimeout))
	}

	addr := &gosocks5.Addr{}
	if _, err := addr.ReadFrom(conn); err != nil {
		log.Error(err)
		io.Copy(io.Discard, conn)
		return err
	}
	ro.Host = addr.String()

	log = log.WithFields(map[string]any{
		"dst": addr.String(),
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

	cc, err := h.options.Router.Dial(ctx, "tcp", addr.String())
	if err != nil {
		return err
	}
	defer cc.Close()

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), addr)
	netpkg.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), addr)

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
