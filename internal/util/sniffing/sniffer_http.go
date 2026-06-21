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

		log = log.WithFields(map[string]any{
			"host": host,
		})

		if ho.bypass != nil && ho.bypass.Contains(ctx, network, host, bypass.WithService(ho.service)) {
			return xbypass.ErrBypass
		}
	}

	dial := ho.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	cc, err := dial(ctx, network, host)
	if err != nil {
		return err
	}
	defer func() { cc.Close() }()

	upstreamHost := host

	log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})

	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()
	ro.Time = time.Time{}

	shouldClose, err := h.httpRoundTrip(ctx, xio.NewReadWriteCloser(br, conn, conn), cc, req, readTimeout, ro, &pStats, log)
	if err != nil || shouldClose {
		return err
	}

	for {
		pStats.Reset()

		req, err := http.ReadRequest(br)
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

		// When DNS override directs multiple domains to the same proxy IP,
		// the browser may reuse a keep-alive connection for a different host.
		// Re-dial to ensure requests reach the correct upstream.
		if reqHost := normalizeHost(req.Host, "80"); reqHost != upstreamHost {
			cc.Close()
			cc, err = dial(ctx, network, reqHost)
			if err != nil {
				return err
			}
			upstreamHost = reqHost
			ro.Host = reqHost
			ro.SrcAddr = cc.LocalAddr().String()
			ro.DstAddr = cc.RemoteAddr().String()
			log = log.WithFields(map[string]any{
				"host": reqHost,
				"src":  cc.LocalAddr().String(),
				"dst":  cc.RemoteAddr().String(),
			})
		}

		if shouldClose, err := h.httpRoundTrip(ctx, xio.NewReadWriteCloser(br, conn, conn), cc, req, readTimeout, ro, &pStats, log); err != nil || shouldClose {
			return err
		}
	}
}

// httpRoundTrip forwards a single HTTP request/response pair and records
// traffic metadata. Returns whether the connection should be closed.
func (h *Sniffer) httpRoundTrip(ctx context.Context, rw, cc io.ReadWriteCloser, req *http.Request, readTimeout time.Duration, ro *xrecorder.HandlerRecorderObject, pStats stats.Stats, log logger.Logger) (close bool, err error) {
	close = true

	ro2 := &xrecorder.HandlerRecorderObject{}
	*ro2 = *ro
	ro = ro2

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
	if bodySize := ClampBodySize(h.RecorderOptions); bodySize > 0 && req.Body != nil {
		reqBody = xhttp.NewBody(req.Body, bodySize)
		req.Body = reqBody
	}

	err = req.Write(cc)

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	if err != nil {
		return
	}

	br := bufio.NewReader(cc)
	var resp *http.Response
	for {
		xio.SetReadDeadline(cc, time.Now().Add(readTimeout))
		resp, err = http.ReadResponse(br, req)
		if err != nil {
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
	if bodySize := ClampBodySize(h.RecorderOptions); bodySize > 0 {
		respBody = xhttp.NewBody(resp.Body, bodySize)
		resp.Body = respBody
	}

	err = resp.Write(rw)

	if respBody != nil {
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	}

	if err != nil {
		err = wrapErr("write response", err)
		return
	}

	if resp.ContentLength >= 0 {
		close = resp.Close
	}

	return
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
