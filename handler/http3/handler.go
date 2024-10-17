package http3

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("http3", NewHandler)
}

type http3Handler struct {
	hop     hop.Hop
	md      metadata
	options handler.Options
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &http3Handler{
		options: options,
	}
}

func (h *http3Handler) Init(md md.Metadata) error {
	if err := h.parseMetadata(md); err != nil {
		return err
	}

	return nil
}

// Forward implements handler.Forwarder.
func (h *http3Handler) Forward(hop hop.Hop) {
	h.hop = hop
}

func (h *http3Handler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	start := time.Now()
	log := h.options.Logger.WithFields(map[string]any{
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
		return nil
	}

	v, ok := conn.(md.Metadatable)
	if !ok || v == nil {
		err := errors.New("wrong connection type")
		log.Error(err)
		return err
	}
	md := v.Metadata()
	return h.roundTrip(ctx,
		md.Get("w").(http.ResponseWriter),
		md.Get("r").(*http.Request),
		log,
	)
}

func (h *http3Handler) roundTrip(ctx context.Context, w http.ResponseWriter, req *http.Request, log logger.Logger) error {
	addr := req.Host
	if _, port, _ := net.SplitHostPort(addr); port == "" {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), "80")
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}

	for k := range h.md.header {
		w.Header().Set(k, h.md.header.Get(k))
	}

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, "udp", addr) {
		w.WriteHeader(http.StatusForbidden)
		log.Debug("bypass: ", addr)
		return nil
	}

	switch h.md.hash {
	case "host":
		ctx = ctxvalue.ContextWithHash(ctx, &ctxvalue.Hash{Source: addr})
	}

	var target *chain.Node
	if h.hop != nil {
		target = h.hop.Select(ctx, hop.HostSelectOption(addr))
	}
	if target == nil {
		err := errors.New("target not available")
		log.Error(err)
		return err
	}

	log = log.WithFields(map[string]any{
		"dst":  fmt.Sprintf("%s/%s", target.Addr, "tcp"),
		"host": target.Addr,
	})

	log.Debugf("%s >> %s", req.RemoteAddr, addr)

	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = "http"
			r.URL.Host = req.Host
			dump, _ := httputil.DumpRequest(r, false)
			log.Debug(string(dump))
		},
		Transport: &http.Transport{
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := h.options.Router.Dial(ctx, network, target.Addr)
				if err != nil {
					log.Error(err)
					// TODO: the router itself may be failed due to the failed node in the router,
					// the dead marker may be a wrong operation.
					if marker := target.Marker(); marker != nil {
						marker.Mark()
					}
				}
				return conn, err
			},
		},
	}

	rp.ServeHTTP(w, req)

	return nil
}

func (h *http3Handler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}
