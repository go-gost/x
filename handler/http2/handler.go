package http2

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	ctxvalue "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	netpkg "github.com/go-gost/x/internal/net"
	stats_util "github.com/go-gost/x/internal/util/stats"
	"github.com/go-gost/x/limiter/traffic/wrapper"
	"github.com/go-gost/x/registry"
	"github.com/go-gost/x/stats"
	stats_wrapper "github.com/go-gost/x/stats/wrapper"
)

func init() {
	registry.HandlerRegistry().Register("http2", NewHandler)
}

type http2Handler struct {
	router  *chain.Router
	md      metadata
	options handler.Options
	stats   *stats_util.HandlerStats
	cancel  context.CancelFunc
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &http2Handler{
		options: options,
		stats:   stats_util.NewHandlerStats(options.Service),
	}
}

func (h *http2Handler) Init(md md.Metadata) error {
	if err := h.parseMetadata(md); err != nil {
		return err
	}

	h.router = h.options.Router
	if h.router == nil {
		h.router = chain.NewRouter(chain.LoggerRouterOption(h.options.Logger))
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel

	if h.options.Observer != nil {
		go h.observeStats(ctx)
	}
	return nil
}

func (h *http2Handler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	start := time.Now()
	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
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

func (h *http2Handler) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	return nil
}

// NOTE: there is an issue (golang/go#43989) will cause the client hangs
// when server returns an non-200 status code,
// May be fixed in go1.18.
func (h *http2Handler) roundTrip(ctx context.Context, w http.ResponseWriter, req *http.Request, log logger.Logger) error {
	// Try to get the actual host.
	// Compatible with GOST 2.x.
	if v := req.Header.Get("Gost-Target"); v != "" {
		if h, err := h.decodeServerName(v); err == nil {
			req.Host = h
		}
	}
	req.Header.Del("Gost-Target")

	if v := req.Header.Get("X-Gost-Target"); v != "" {
		if h, err := h.decodeServerName(v); err == nil {
			req.Host = h
		}
	}
	req.Header.Del("X-Gost-Target")

	addr := req.Host
	if _, port, _ := net.SplitHostPort(addr); port == "" {
		addr = net.JoinHostPort(addr, "80")
	}

	fields := map[string]any{
		"dst": addr,
	}
	if u, _, _ := h.basicProxyAuth(req.Header.Get("Proxy-Authorization")); u != "" {
		fields["user"] = u
	}
	log = log.WithFields(fields)

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}
	log.Debugf("%s >> %s", req.RemoteAddr, addr)

	for k := range h.md.header {
		w.Header().Set(k, h.md.header.Get(k))
	}

	resp := &http.Response{
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte{})),
	}

	clientID, ok := h.authenticate(ctx, w, req, resp, log)
	if !ok {
		return nil
	}
	ctx = ctxvalue.ContextWithClientID(ctx, ctxvalue.ClientID(clientID))

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, "tcp", addr) {
		w.WriteHeader(http.StatusForbidden)
		log.Debug("bypass: ", addr)
		return nil
	}

	// delete the proxy related headers.
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")

	switch h.md.hash {
	case "host":
		ctx = ctxvalue.ContextWithHash(ctx, &ctxvalue.Hash{Source: addr})
	}

	cc, err := h.router.Dial(ctx, "tcp", addr)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return err
	}
	defer cc.Close()

	if req.Method == http.MethodConnect {
		w.WriteHeader(http.StatusOK)
		if fw, ok := w.(http.Flusher); ok {
			fw.Flush()
		}

		// compatible with HTTP1.x
		if hj, ok := w.(http.Hijacker); ok && req.ProtoMajor == 1 {
			// we take over the underly connection
			conn, _, err := hj.Hijack()
			if err != nil {
				log.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return err
			}
			defer conn.Close()

			start := time.Now()
			log.Infof("%s <-> %s", conn.RemoteAddr(), addr)
			netpkg.Transport(conn, cc)
			log.WithFields(map[string]any{
				"duration": time.Since(start),
			}).Infof("%s >-< %s", conn.RemoteAddr(), addr)

			return nil
		}

		rw := wrapper.WrapReadWriter(h.options.Limiter, xio.NewReadWriter(req.Body, flushWriter{w}),
			traffic.NetworkOption("tcp"),
			traffic.AddrOption(addr),
			traffic.ClientOption(clientID),
			traffic.SrcOption(req.RemoteAddr),
		)
		if h.options.Observer != nil {
			pstats := h.stats.Stats(clientID)
			pstats.Add(stats.KindTotalConns, 1)
			pstats.Add(stats.KindCurrentConns, 1)
			defer pstats.Add(stats.KindCurrentConns, -1)
			rw = stats_wrapper.WrapReadWriter(rw, pstats)
		}

		start := time.Now()
		log.Infof("%s <-> %s", req.RemoteAddr, addr)
		netpkg.Transport(rw, cc)
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >-< %s", req.RemoteAddr, addr)
		return nil
	}

	// TODO: forward request
	return nil
}

func (h *http2Handler) decodeServerName(s string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(b) < 4 {
		return "", errors.New("invalid name")
	}
	v, err := base64.RawURLEncoding.DecodeString(string(b[4:]))
	if err != nil {
		return "", err
	}
	if crc32.ChecksumIEEE(v) != binary.BigEndian.Uint32(b[:4]) {
		return "", errors.New("invalid name")
	}
	return string(v), nil
}

func (h *http2Handler) basicProxyAuth(proxyAuth string) (username, password string, ok bool) {
	if proxyAuth == "" {
		return
	}

	if !strings.HasPrefix(proxyAuth, "Basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(proxyAuth, "Basic "))
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}

	return cs[:s], cs[s+1:], true
}

func (h *http2Handler) authenticate(ctx context.Context, w http.ResponseWriter, r *http.Request, resp *http.Response, log logger.Logger) (id string, ok bool) {
	u, p, _ := h.basicProxyAuth(r.Header.Get("Proxy-Authorization"))
	if h.options.Auther == nil {
		return "", true
	}
	if id, ok = h.options.Auther.Authenticate(ctx, u, p); ok {
		return
	}

	pr := h.md.probeResistance
	// probing resistance is enabled, and knocking host is mismatch.
	if pr != nil && (pr.Knock == "" || !strings.EqualFold(r.URL.Hostname(), pr.Knock)) {
		resp.StatusCode = http.StatusServiceUnavailable // default status code
		switch pr.Type {
		case "code":
			resp.StatusCode, _ = strconv.Atoi(pr.Value)
		case "web":
			url := pr.Value
			if !strings.HasPrefix(url, "http") {
				url = "http://" + url
			}
			r, err := http.Get(url)
			if err != nil {
				log.Error(err)
				break
			}
			resp = r
			defer resp.Body.Close()
		case "host":
			cc, err := net.Dial("tcp", pr.Value)
			if err != nil {
				log.Error(err)
				break
			}
			defer cc.Close()

			if err := h.forwardRequest(w, r, cc); err != nil {
				log.Error(err)
			}
			return
		case "file":
			f, _ := os.Open(pr.Value)
			if f != nil {
				defer f.Close()

				resp.StatusCode = http.StatusOK
				if finfo, _ := f.Stat(); finfo != nil {
					resp.ContentLength = finfo.Size()
				}
				resp.Header.Set("Content-Type", "text/html")
				resp.Body = f
			}
		}
	}

	if resp.StatusCode == 0 {
		realm := defaultRealm
		if h.md.authBasicRealm != "" {
			realm = h.md.authBasicRealm
		}
		resp.StatusCode = http.StatusProxyAuthRequired
		resp.Header.Add("Proxy-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", realm))
		if strings.ToLower(r.Header.Get("Proxy-Connection")) == "keep-alive" {
			// XXX libcurl will keep sending auth request in same conn
			// which we don't supported yet.
			resp.Header.Set("Connection", "close")
			resp.Header.Set("Proxy-Connection", "close")
		}

		log.Debug("proxy authentication required")
	} else {
		resp.Header = http.Header{}
		// resp.Header.Set("Server", "nginx/1.20.1")
		// resp.Header.Set("Date", time.Now().Format(http.TimeFormat))
		if resp.StatusCode == http.StatusOK {
			resp.Header.Set("Connection", "keep-alive")
		}
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	h.writeResponse(w, resp)

	return
}
func (h *http2Handler) forwardRequest(w http.ResponseWriter, r *http.Request, rw io.ReadWriter) (err error) {
	if err = r.Write(rw); err != nil {
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(rw), r)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	return h.writeResponse(w, resp)
}

func (h *http2Handler) writeResponse(w http.ResponseWriter, resp *http.Response) error {
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err := io.Copy(flushWriter{w}, resp.Body)
	return err
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

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.options.Observer.Observe(ctx, h.stats.Events())
		case <-ctx.Done():
			return
		}
	}
}
