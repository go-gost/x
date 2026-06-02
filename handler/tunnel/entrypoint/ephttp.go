package entrypoint

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

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	"github.com/go-gost/x/internal/util/sniffing"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"golang.org/x/net/http/httpguts"
)

// HTTP header names used for tunnel loop detection and session tracking.
const (
	// httpHeaderSID carries the session ID from the external request
	// through the tunnel to the internal service.
	httpHeaderSID = "Gost-Sid"
	// httpHeaderForwardedNode carries the node ID chain from each
	// entrypoint the request has traversed. Used for loop detection:
	// if the header already contains our node, the request is looping
	// and is rejected with 503.
	httpHeaderForwardedNode = "Gost-Forwarded-Node"
)

// handleHTTP processes an HTTP request arriving at the entrypoint.
//
// Flow:
//  1. Read HTTP request from the public connection.
//  2. Record request metadata in ro.HTTP.
//  3. httpRoundTrip: shallow-copy ro, check forwarding loop,
//     build http.Request, call ep.transport.RoundTrip() which
//     uses ep.dial() as DialContext — that resolves ingress rules
//     to a tunnelID, calls Dialer.Dial(), and writes relay address
//     features into the mux stream.
//  4. Handle WebSocket upgrade via handleUpgradeResponse (sniffing).
//  5. Continue in a loop for keep-alive: read next request, repeat.
//
// HTTP request body recording: if recorder options specify HTTPBody,
// the request body is wrapped in a xhttp.Body for capture.
func (ep *Entrypoint) handleHTTP(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (err error) {
	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
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

	ro.Time = time.Time{}

	if err := ep.httpRoundTrip(ctx, xio.NewReadWriteCloser(br, conn, conn), req, ro, &pStats, log); err != nil {
		log.Error(err)
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

		if err := ep.httpRoundTrip(ctx, xio.NewReadWriteCloser(br, conn, conn), req, ro, &pStats, log); err != nil {
			return err
		}
	}
}

func (ep *Entrypoint) httpRoundTrip(ctx context.Context, rw io.ReadWriteCloser, req *http.Request, ro *xrecorder.HandlerRecorderObject, pStats stats.Stats, log logger.Logger) (err error) {
	ro2 := &xrecorder.HandlerRecorderObject{}
	*ro2 = *ro
	ro = ro2

	if sid := req.Header.Get(httpHeaderSID); sid != "" {
		ro.SID = sid
	} else {
		req.Header.Set(httpHeaderSID, ro.SID)
	}

	// Loop detection: if Gost-Forwarded-Node contains our own node ID,
	// the request has already passed through this entrypoint and is looping.
	for _, node := range strings.Split(req.Header.Get(httpHeaderForwardedNode), ",") {
		if strings.TrimSpace(node) == ep.node {
			log.Warn("forwarding loop detected, rejecting request")
			res := &http.Response{
				ProtoMajor: req.ProtoMajor,
				ProtoMinor: req.ProtoMinor,
				Header:     http.Header{},
				StatusCode: http.StatusServiceUnavailable,
			}
			ro.HTTP.StatusCode = res.StatusCode
			res.Write(rw)
			return nil
		}
	}

	req.Header.Set(httpHeaderForwardedNode, ro.Node)

	host := req.Host
	if _, port, _ := net.SplitHostPort(host); port == "" {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
	}
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
		if err := ro.Record(ctx, ep.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(ro.Time),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >-< %s", ro.RemoteAddr, req.Host)
	}()

	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
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

	res := &http.Response{
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		StatusCode: http.StatusServiceUnavailable,
	}
	ro.HTTP.StatusCode = res.StatusCode

	var reqBody *xhttp.Body
	if opts := ep.recorder.Options; opts != nil && opts.HTTPBody {
		if req.Body != nil {
			bodySize := opts.MaxBodySize
			if bodySize <= 0 {
				bodySize = sniffing.DefaultBodySize
			}
			if bodySize > sniffing.MaxBodySize {
				bodySize = sniffing.MaxBodySize
			}
			reqBody = xhttp.NewBody(req.Body, bodySize)
			req.Body = reqBody
		}
	}

	if clientIP := xhttp.GetClientIP(req); clientIP != nil {
		ro.ClientIP = clientIP.String()
		ctx = xctx.ContextWithSrcAddr(ctx, (&net.TCPAddr{IP: clientIP}))
	}

	ctx = ictx.ContextWithRecorderObject(ctx, ro)
	ctx = ictx.ContextWithLogger(ctx, log)

	resp, err := ep.transport.RoundTrip(req.WithContext(ctx))

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	if err != nil {
		if errors.Is(err, errNoRoute) || errors.Is(err, errPrivateTunnel) {
			res.StatusCode = http.StatusBadGateway
			ro.HTTP.StatusCode = http.StatusBadGateway
		}
		res.Write(rw)
		return nil
	}
	defer resp.Body.Close()

	ro.HTTP.StatusCode = resp.StatusCode
	ro.HTTP.Response.Header = resp.Header
	ro.HTTP.Response.ContentLength = resp.ContentLength

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		return ep.handleUpgradeResponse(ctx, rw, req, resp, ro, log)
	}

	var respBody *xhttp.Body
	if opts := ep.recorder.Options; opts != nil && opts.HTTPBody {
		bodySize := opts.MaxBodySize
		if bodySize <= 0 {
			bodySize = sniffing.DefaultBodySize
		}
		if bodySize > sniffing.MaxBodySize {
			bodySize = sniffing.MaxBodySize
		}
		respBody = xhttp.NewBody(resp.Body, bodySize)
		resp.Body = respBody
	}

	err = resp.Write(rw)

	if respBody != nil {
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	}

	if err != nil {
		return fmt.Errorf("write response: %v", err)
	}

	return
}

// upgradeType returns the upgrade protocol from an HTTP header set,
// or empty string if the request/response does not include an Upgrade.
func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

// handleUpgradeResponse handles an HTTP upgrade (101 Switching Protocols).
//
// It validates that the upgrade protocol matches between request and response,
// writes the response to the client, and then pipes the raw connection.
// For WebSocket upgrades with sniffing enabled, it delegates to
// sniffingWebsocketFrame for frame-level recording.
func (ep *Entrypoint) handleUpgradeResponse(ctx context.Context, rw io.ReadWriteCloser, req *http.Request, res *http.Response, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if !strings.EqualFold(reqUpType, resUpType) {
		return fmt.Errorf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType)
	}

	backConn, ok := res.Body.(io.ReadWriteCloser)
	if !ok {
		return fmt.Errorf("internal error: 101 switching protocols response with non-writable body")
	}
	defer backConn.Close()

	res.Body = nil
	if err := res.Write(rw); err != nil {
		return fmt.Errorf("response write: %v", err)
	}

	if reqUpType == "websocket" && ep.sniffingWebsocket {
		return ep.sniffingWebsocketFrame(ctx, rw, backConn, ro, log)
	}

	return xnet.Pipe(ctx, rw, backConn)
}