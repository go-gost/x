package http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/go-gost/core/bypass"
	stats "github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/logger"
	xbypass "github.com/go-gost/x/bypass"
	ictx "github.com/go-gost/x/internal/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	"github.com/go-gost/x/internal/util/sniffing"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
)

// handleProxy implements HTTP forward proxy semantics. It wraps the
// connection for stats, performs the first round-trip, and then enters
// a keep-alive loop reading and proxying subsequent requests on the
// same connection until the client or upstream closes.
//
// Each request is processed through proxyRoundTrip, which handles
// authentication header stripping, bypass checks, and body recording.
func (h *httpHandler) handleProxy(ctx context.Context, conn net.Conn, req *http.Request, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	ro.Time = time.Time{}

	if close, err := h.proxyRoundTrip(ctx, conn, req, ro, &pStats, log); err != nil || close {
		return err
	}

	// Keep-alive loop: read and proxy subsequent requests.
	br := bufio.NewReader(conn)
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

		if close, err := h.proxyRoundTrip(ctx, xio.NewReadWriteCloser(br, conn, conn), req, ro, &pStats, log); err != nil || close {
			req.Body.Close()
			return err
		}
		req.Body.Close()
	}
}

// proxyRoundTrip performs a single HTTP round-trip for a forward proxy
// request. It:
//
//   - Clones the recorder object for per-request isolation.
//   - Normalises the host and adds a default port if missing.
//   - Adjusts HTTP/1.0 Connection headers for compatibility.
//   - Strips proxy-specific headers (Proxy-Authorization, Gost-Target, etc.).
//   - Checks bypass rules — forbidden hosts get a 403.
//   - Optionally captures the request body for recording.
//   - Sends the request through the upstream transport.
//   - Optionally captures the response body for recording.
//   - Handles 101 Switching Protocols (WebSocket upgrades).
//
// The close return value indicates whether the underlying connection
// should be closed after this round-trip (e.g. HTTP/1.0 without keep-alive,
// or an upstream Connection: close).
func (h *httpHandler) proxyRoundTrip(ctx context.Context, rw io.ReadWriteCloser, req *http.Request, ro *xrecorder.HandlerRecorderObject, pStats stats.Stats, log logger.Logger) (close bool, err error) {
	close = true

	// Clone the recorder object so per-request mutations don't leak.
	ro2 := &xrecorder.HandlerRecorderObject{}
	*ro2 = *ro
	ro = ro2

	host := normalizeHostPort(req.Host, "80")
	ro.Host = host
	ro.Time = time.Now()

	log = log.WithFields(map[string]any{
		"host": host,
	})

	log.Infof("%s <-> %s", ro.RemoteAddr, req.Host)
	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(ro.Time)
		if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
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

	// HTTP/1.0: ensure Connection: close unless the client explicitly
	// requested keep-alive (which we translate by removing the header
	// so the default close behaviour applies).
	http10 := req.ProtoMajor == 1 && req.ProtoMinor == 0
	if http10 {
		if strings.ToLower(req.Header.Get("Connection")) == "keep-alive" {
			req.Header.Del("Connection")
		} else {
			req.Header.Set("Connection", "close")
		}
	}

	// Strip hop-by-hop proxy headers before forwarding.
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Gost-Target")
	req.Header.Del("X-Gost-Target")

	res := &http.Response{
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		StatusCode: http.StatusServiceUnavailable,
	}
	ro.HTTP.StatusCode = res.StatusCode

	if h.options.Bypass != nil &&
		h.options.Bypass.Contains(ctx, "tcp", host, bypass.WithService(h.options.Service)) {
		res.StatusCode = http.StatusForbidden

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(res, false)
			log.Trace(string(dump))
		}
		log.Debug("bypass: ", host)
		if werr := res.Write(rw); werr != nil {
			log.Error("write bypass response: ", werr)
		}
		err = xbypass.ErrBypass
		return
	}

	// Optionally intercept the request body for recording. The original
	// body is replaced with a tee reader so the transport still sees it.
	var reqBody *xhttp.Body
	if bodySize := sniffing.ClampBodySize(h.recorder.Options); bodySize > 0 && req.Body != nil {
		reqBody = xhttp.NewBody(req.Body, bodySize)
		req.Body = reqBody
	}

	ctx = ictx.ContextWithRecorderObject(ctx, ro)
	ctx = ictx.ContextWithLogger(ctx, log)

	resp, err := h.transport.RoundTrip(req.WithContext(ctx))

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	if err != nil {
		if werr := res.Write(rw); werr != nil {
			log.Error("write error response: ", werr)
		}
		return
	}
	defer resp.Body.Close()

	ro.HTTP.StatusCode = resp.StatusCode
	ro.HTTP.Response.Header = resp.Header.Clone()
	ro.HTTP.Response.ContentLength = resp.ContentLength

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	// HTTP/1.0: propagate keep-alive if the upstream supports it, and
	// force the response protocol version to 1.0.
	if http10 {
		if !resp.Close {
			resp.Header.Set("Connection", "keep-alive")
		}
		resp.ProtoMajor = 1
		resp.ProtoMinor = 0
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		err = h.handleUpgradeResponse(ctx, rw, req, resp, ro, log)
		return
	}

	// Optionally intercept the response body for recording.
	var respBody *xhttp.Body
	if bodySize := sniffing.ClampBodySize(h.recorder.Options); bodySize > 0 {
		respBody = xhttp.NewBody(resp.Body, bodySize)
		resp.Body = respBody
	}

	err = resp.Write(rw)

	if respBody != nil {
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	}

	if err != nil {
		err = fmt.Errorf("write response: %v", err)
		return
	}

	close = resp.Close

	return
}

// handleUpgradeResponse handles HTTP 101 Switching Protocols responses.
// It validates that the request and response upgrade types match, writes
// the 101 response back to the client, and then relays raw bytes between
// the client and the backend connection.
//
// If the upgrade is to "websocket" and WebSocket sniffing is enabled,
// frame-level recording is performed via sniffingWebsocketFrame.
func (h *httpHandler) handleUpgradeResponse(ctx context.Context, rw io.ReadWriteCloser, req *http.Request, res *http.Response, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if !strings.EqualFold(reqUpType, resUpType) {
		return fmt.Errorf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType)
	}

	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		return fmt.Errorf("internal error: 101 switching protocols response with non-writable body")
	}

	res.Body = nil
	if err := res.Write(rw); err != nil {
		return fmt.Errorf("response write: %v", err)
	}

	if reqUpType == "websocket" && h.md.sniffingWebsocket {
		return h.sniffingWebsocketFrame(ctx, rw, backConn, ro, log)
	}

	return xnet.Pipe(ctx, rw, backConn, xnet.WithReadTimeout(h.md.idleTimeout))
}
