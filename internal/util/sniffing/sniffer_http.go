package sniffing

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	xbypass "github.com/go-gost/x/bypass"
	xctx "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	"github.com/go-gost/x/internal/util/httpcache"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
)

// HandleHTTP sniffs and proxies an HTTP connection. It reads the initial
// request, applies bypass rules, and forwards traffic to the upstream.
func (h *Sniffer) HandleHTTP(ctx context.Context, network string, conn net.Conn, opts ...HandleOption) error {
	var ho HandleOptions
	for _, opt := range opts {
		opt(&ho)
	}

	readTimeout := h.effectiveReadTimeout()

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}

	log := ho.log
	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}

	ro := ho.recorderObject

	if clientIP := xhttp.GetClientIP(req); clientIP != nil {
		ro.ClientIP = clientIP.String()
		ctx = xctx.ContextWithSrcAddr(ctx, &net.TCPAddr{IP: clientIP})
	}

	// http/2
	if req.Method == "PRI" && len(req.Header) == 0 && req.URL.Path == "*" && req.Proto == "HTTP/2.0" {
		return h.serveH2(ctx, network, xnet.NewReadWriteConn(br, conn, conn), &ho)
	}

	host := normalizeHost(req.Host, "80")
	if host != "" {
		ro.Host = host
		log = log.WithFields(map[string]any{"host": host})

		if ho.bypass != nil && ho.bypass.Contains(ctx, network, host, bypass.WithService(ho.service)) {
			return xbypass.ErrBypass
		}
	}

	dialFn := ho.dial
	if dialFn == nil {
		dialFn = (&net.Dialer{}).DialContext
	}

	var (
		cc           net.Conn
		upstreamHost string
	)

	for {
		// Initialize HTTP recorder fields for this request.
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

		// --- Cache check before any upstream dial ---
		var (
			staleResp *http.Response
			freshHit  bool
		)
		if h.Cache != nil && h.Cache.CacheableRequest(req) {
			if cachedResp, stale, ok := h.Cache.Lookup(ctx, req); ok {
				if !stale {
					if h.serveCachedResponse(ctx, conn, req, cachedResp, ro, log) {
						return nil
					}
					freshHit = true
				} else {
					staleResp = cachedResp
				}
			}
		}

		// --- Dial upstream (miss or stale; fresh cache hit with keep-alive skips) ---
		if !freshHit {
			if cc == nil {
				cc, err = dialFn(ctx, network, host)
				if err != nil {
					if staleResp != nil && h.Cache != nil && h.Cache.ServeStale() {
						ro.Time = time.Now()
						ro.HTTP.StatusCode = staleResp.StatusCode
						staleResp.Write(conn)
						if cl := staleResp.ContentLength; cl > 0 {
							ro.OutputBytes = uint64(cl)
						}
						ro.Duration = time.Since(ro.Time)
						if rerr := ro.Record(ctx, h.Recorder); rerr != nil {
							log.Errorf("record: %v", rerr)
						}
						staleResp.Body.Close()
						return nil
					}
					return err
				}
				upstreamHost = host

				log = log.WithFields(map[string]any{
					"src": cc.LocalAddr().String(),
					"dst": cc.RemoteAddr().String(),
				})

				ro.SrcAddr = cc.LocalAddr().String()
				ro.DstAddr = cc.RemoteAddr().String()
			}

			// --- Forward request and cache response ---
			shouldClose, err := h.httpRoundTrip(ctx, xio.NewReadWriteCloser(br, conn, conn), cc, req, readTimeout, ro, &pStats, log, staleResp)
			if staleResp != nil && staleResp.Body != nil {
				staleResp.Body.Close()
			}
			if err != nil || shouldClose {
				return err
			}
		}

		// --- Read next request (keep-alive) ---
		req, err = http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpRequest(req, false)
			log.Trace(string(dump))
		}

		// Re-dial on host change (DNS override reuses same conn for same host).
		if reqHost := normalizeHost(req.Host, "80"); reqHost != "" && reqHost != upstreamHost {
			cc.Close()
			cc = nil
			host = reqHost
			ro.Host = reqHost

			log = log.WithFields(map[string]any{"host": reqHost})
		}
	}
}

// serveCachedResponse writes resp to rw, records the cache hit in ro, and
// returns whether the client connection should close after the response.
func (h *Sniffer) serveCachedResponse(ctx context.Context, rw io.Writer, req *http.Request, resp *http.Response, ro *xrecorder.HandlerRecorderObject, log logger.Logger) bool {
	defer resp.Body.Close()
	ro.Time = time.Now()
	ro.HTTP.StatusCode = resp.StatusCode
	ro.HTTP.Response.Header = resp.Header.Clone()
	ro.HTTP.Response.ContentLength = resp.ContentLength
	log.Debugf("cache hit: %s", httpcache.Key(req.Method, req.Host, req.RequestURI))
	if err := resp.Write(rw); err != nil {
		log.Errorf("write cached response: %v", err)
		return true
	}
	close := true
	if resp.ContentLength >= 0 {
		close = resp.Close
	}
	if cl := ro.HTTP.Response.ContentLength; cl > 0 {
		ro.OutputBytes = uint64(cl)
	}
	ro.Duration = time.Since(ro.Time)
	if rerr := ro.Record(ctx, h.Recorder); rerr != nil {
		log.Errorf("record: %v", rerr)
	}
	log.WithFields(map[string]any{
		"duration":    ro.Duration,
		"inputBytes":  ro.InputBytes,
		"outputBytes": ro.OutputBytes,
	}).Infof("%s >-< %s", ro.RemoteAddr, req.Host)
	return close
}

// httpRoundTrip forwards a single HTTP request/response pair and records
// traffic metadata. Returns whether the connection should be closed.
// staleResp, when non-nil, is written to the client on upstream read failure
// when the cache policy enables serve-stale.
func (h *Sniffer) httpRoundTrip(ctx context.Context, rw, cc io.ReadWriteCloser, req *http.Request, readTimeout time.Duration, ro *xrecorder.HandlerRecorderObject, pStats stats.Stats, log logger.Logger, staleResp *http.Response) (close bool, err error) {
	close = true

	ro2 := &xrecorder.HandlerRecorderObject{}
	*ro2 = *ro
	ro = ro2

	if v := req.Header.Get("Gost-Record"); v != "" {
		ro.RecordMode = strings.ToLower(v)
	}
	req.Header.Del("Gost-Record")

	ro.Time = time.Now()
	log.Infof("%s <-> %s", ro.RemoteAddr, req.Host)
	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(ro.Time)
		if rerr := ro.Record(ctx, h.Recorder); rerr != nil {
			log.Errorf("record: %v", rerr)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(ro.Time),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >-< %s", ro.RemoteAddr, req.Host)
	}()

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

	// HTTP/1.0
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		if strings.ToLower(req.Header.Get("Connection")) == "keep-alive" {
			req.Header.Del("Connection")
		} else {
			req.Header.Set("Connection", "close")
		}
	}

	var reqBody *xhttp.Body
	if bodySize := ClampBodySize(h.RecorderOptions); bodySize > 0 && req.Body != nil && ro.RecordMode != "headers" && ro.RecordMode != "off" {
		reqBody = xhttp.NewBody(req.Body, bodySize)
		req.Body = reqBody
	}

	err = req.Write(cc)

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	if err != nil {
		if h.serveStale(rw, staleResp, ro, &close, log) {
			err = nil
			return
		}
		return
	}

	br := bufio.NewReader(cc)
	var resp *http.Response
	for {
		xio.SetReadDeadline(cc, time.Now().Add(readTimeout))
		resp, err = http.ReadResponse(br, req)
		if err != nil {
			if h.serveStale(rw, staleResp, ro, &close, log) {
				err = nil
				return
			}
			err = wrapErr("read response", err)
			return
		}
		if resp.StatusCode == http.StatusContinue {
			resp.Write(rw)
			resp.Body.Close()
			continue
		}

		break
	}
	defer resp.Body.Close()
	xio.SetReadDeadline(cc, time.Time{})

	ro.HTTP.StatusCode = resp.StatusCode
	ro.HTTP.Response.Header = resp.Header.Clone()
	ro.HTTP.Response.ContentLength = resp.ContentLength

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		h.handleUpgradeResponse(ctx, rw, cc, req, resp, ro, log)
		return
	}

	// HTTP/1.0
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		if !resp.Close {
			resp.Header.Set("Connection", "keep-alive")
		}
		resp.ProtoMajor = req.ProtoMajor
		resp.ProtoMinor = req.ProtoMinor
	}

	var respBody *xhttp.Body
	if bodySize := ClampBodySize(h.RecorderOptions); bodySize > 0 && ro.RecordMode != "headers" && ro.RecordMode != "off" {
		respBody = xhttp.NewBody(resp.Body, bodySize)
		resp.Body = respBody
	}

	// Response cache: tee the response so a copy is captured while it streams
	// to the client, then store it on success.
	var writeTarget io.Writer = rw
	var tee *httpcache.TeeWriter
	if h.Cache != nil && h.Cache.Cacheable(req, resp) {
		tee = h.Cache.TeeWriter(rw)
		writeTarget = tee
	}

	err = resp.Write(writeTarget)

	if respBody != nil {
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	}

	if err != nil {
		err = wrapErr("write response", err)
		return
	}

	if tee != nil {
		if data := tee.Captured(); data != nil {
			if serr := h.Cache.Store(ctx, req, data, resp.StatusCode); serr != nil {
				log.Warnf("cache store: %v", serr)
			} else {
				log.Debugf("cache store: %s", httpcache.Key(req.Method, req.Host, req.RequestURI))
			}
		}
	}

	if resp.ContentLength >= 0 {
		close = resp.Close
	}

	return
}

// serveStale writes a stale (expired) cached response to the client when the
// upstream fetch failed and the cache policy allows serving stale. It reports
// whether a stale response was served.
func (h *Sniffer) serveStale(rw io.Writer, staleResp *http.Response, ro *xrecorder.HandlerRecorderObject, close *bool, log logger.Logger) bool {
	if h.Cache == nil || staleResp == nil || !h.Cache.ServeStale() {
		return false
	}
	ro.HTTP.StatusCode = staleResp.StatusCode
	log.Debugf("cache serve-stale: %d", staleResp.StatusCode)
	if werr := staleResp.Write(rw); werr != nil {
		log.Errorf("write stale response: %v", werr)
		return false
	}
	if staleResp.ContentLength >= 0 {
		*close = staleResp.Close
	}
	return true
}

// wrapErr formats an error with a context message.
func wrapErr(msg string, err error) error {
	return &wrappedErr{msg: msg, err: err}
}

type wrappedErr struct {
	msg string
	err error
}

func (e *wrappedErr) Error() string {
	return e.msg + ": " + e.err.Error()
}

func (e *wrappedErr) Unwrap() error {
	return e.err
}
