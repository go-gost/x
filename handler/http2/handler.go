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

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	xbypass "github.com/go-gost/x/bypass"
	ctxvalue "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	stats_util "github.com/go-gost/x/internal/util/stats"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	cache_limiter "github.com/go-gost/x/limiter/traffic/cache"
	traffic_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
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
	if err := h.parseMetadata(md); err != nil {
		return err
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
		SID:        string(ctxvalue.SidFromContext(ctx)),
	}
	ro.ClientIP, _, _ = net.SplitHostPort(conn.RemoteAddr().String())

	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
		"client": ro.ClientIP,
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

	v, ok := conn.(md.Metadatable)
	if !ok || v == nil {
		err = errors.New("wrong connection type")
		log.Error(err)
		return err
	}

	md := v.Metadata()
	return h.roundTrip(ctx,
		md.Get("w").(http.ResponseWriter),
		md.Get("r").(*http.Request),
		ro,
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
func (h *http2Handler) roundTrip(ctx context.Context, w http.ResponseWriter, req *http.Request, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	// Try to get the actual host.
	// Compatible with GOST 2.x.
	if v := req.Header.Get("Gost-Target"); v != "" {
		if h, err := h.decodeServerName(v); err == nil {
			req.Host = h
		}
	}
	if v := req.Header.Get("X-Gost-Target"); v != "" {
		if h, err := h.decodeServerName(v); err == nil {
			req.Host = h
		}
	}

	if clientIP := xhttp.GetClientIP(req); clientIP != nil {
		ro.ClientIP = clientIP.String()
	}

	host := req.Host
	if _, port, _ := net.SplitHostPort(host); port == "" {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
	}
	ro.Host = host

	fields := map[string]any{
		"dst":  host,
		"host": host,
	}
	if u, _, _ := h.basicProxyAuth(req.Header.Get("Proxy-Authorization")); u != "" {
		fields["user"] = u
		ro.ClientID = u
	}
	log = log.WithFields(fields)

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}
	log.Debugf("%s >> %s", req.RemoteAddr, host)

	for k := range h.md.header {
		w.Header().Set(k, h.md.header.Get(k))
	}

	resp := &http.Response{
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     w.Header(),
		Body:       io.NopCloser(bytes.NewReader([]byte{})),
	}

	ro.HTTP = &xrecorder.HTTPRecorderObject{
		Host:   req.Host,
		Proto:  req.Proto,
		Scheme: req.URL.Scheme,
		Method: req.Method,
		URI:    req.RequestURI,
		Request: xrecorder.HTTPRequestRecorderObject{
			ContentLength: req.ContentLength,
			Header:        req.Header.Clone(),
		},
	}
	defer func() {
		ro.HTTP.StatusCode = resp.StatusCode
		ro.HTTP.Response.Header = resp.Header
	}()

	clientID, ok := h.authenticate(ctx, w, req, resp, log)
	if !ok {
		return errors.New("authentication failed")
	}
	ctx = ctxvalue.ContextWithClientID(ctx, ctxvalue.ClientID(clientID))

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, "tcp", host) {
		resp.StatusCode = http.StatusForbidden
		w.WriteHeader(resp.StatusCode)
		log.Debug("bypass: ", host)
		return xbypass.ErrBypass
	}

	// delete the proxy related headers.
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Gost-Target")
	req.Header.Del("X-Gost-Target")

	switch h.md.hash {
	case "host":
		ctx = ctxvalue.ContextWithHash(ctx, &ctxvalue.Hash{Source: host})
	}

	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &buf), "tcp", host)
	ro.Route = buf.String()
	if err != nil {
		log.Error(err)
		resp.StatusCode = http.StatusServiceUnavailable
		w.WriteHeader(resp.StatusCode)
		return err
	}
	defer cc.Close()

	if req.Method == http.MethodConnect {
		resp.StatusCode = http.StatusOK
		w.WriteHeader(http.StatusOK)
		if fw, ok := w.(http.Flusher); ok {
			fw.Flush()
		}

		rw := xio.NewReadWriter(req.Body, flushWriter{w})

		// compatible with HTTP1.x
		if hj, ok := w.(http.Hijacker); ok && req.ProtoMajor == 1 {
			// we take over the underly connection
			conn, _, err := hj.Hijack()
			if err != nil {
				log.Error(err)
				resp.StatusCode = http.StatusInternalServerError
				w.WriteHeader(http.StatusInternalServerError)
				return err
			}
			defer conn.Close()

			rw = conn
		}

		rw = traffic_wrapper.WrapReadWriter(
			h.limiter,
			rw,
			clientID,
			limiter.ScopeOption(limiter.ScopeClient),
			limiter.ServiceOption(h.options.Service),
			limiter.NetworkOption("tcp"),
			limiter.AddrOption(host),
			limiter.ClientOption(clientID),
			limiter.SrcOption(req.RemoteAddr),
		)
		if h.options.Observer != nil {
			pstats := h.stats.Stats(clientID)
			pstats.Add(stats.KindTotalConns, 1)
			pstats.Add(stats.KindCurrentConns, 1)
			defer pstats.Add(stats.KindCurrentConns, -1)
			rw = stats_wrapper.WrapReadWriter(rw, pstats)
		}

		start := time.Now()
		log.Infof("%s <-> %s", req.RemoteAddr, host)
		xnet.Transport(rw, cc)
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >-< %s", req.RemoteAddr, host)
		return nil
	}

	// TODO: forward request
	resp.StatusCode = http.StatusBadRequest
	w.WriteHeader(resp.StatusCode)
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
