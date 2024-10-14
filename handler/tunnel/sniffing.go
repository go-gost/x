package tunnel

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
	"github.com/go-gost/relay"
	ctxvalue "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
)

const (
	defaultBodySize = 1024 * 1024 // 1MB
)

func (h *entrypoint) handleHTTP(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	pStats := stats.Stats{}
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

	if clientIP := xhttp.GetClientIP(req); clientIP != nil {
		ro.ClientIP = clientIP.String()
	}

	clientAddr := ro.RemoteAddr
	if ro.ClientIP != "" {
		if _, port, _ := net.SplitHostPort(ro.RemoteAddr); port != "" {
			clientAddr = net.JoinHostPort(ro.ClientIP, port)
		}
	}
	ctx = ctxvalue.ContextWithClientAddr(ctx, ctxvalue.ClientAddr(clientAddr))

	res := &http.Response{
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		StatusCode: http.StatusServiceUnavailable,
	}
	ro.HTTP.StatusCode = res.StatusCode

	host := req.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
	}

	cc, node, tunnel, err := h.dial(ctx, conn, host, res, ro, log)
	if err != nil {
		log.Error(err)
		return err
	}
	defer cc.Close()

	log = log.WithFields(map[string]any{
		"host":     host,
		"tunnel":   tunnel,
		"clientIP": ro.ClientIP,
	})

	if node == h.node {
		var features []relay.Feature
		af := &relay.AddrFeature{}
		af.ParseFrom(clientAddr)
		features = append(features, af) // src address

		af = &relay.AddrFeature{}
		af.ParseFrom(host)
		features = append(features, af) // dst address

		if _, err := (&relay.Response{
			Version:  relay.Version1,
			Status:   relay.StatusOK,
			Features: features,
		}).WriteTo(cc); err != nil {
			log.Error(err)
			res.Write(conn)
			return err
		}
	}

	shouldClose, err := h.httpRoundTrip(ctx, conn, cc, req, ro, &pStats, log)
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

		if shouldClose, err := h.httpRoundTrip(ctx, conn, cc, req, ro, &pStats, log); err != nil || shouldClose {
			return err
		}
	}
}

func (h *entrypoint) dial(ctx context.Context, conn net.Conn, host string, res *http.Response, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (cc net.Conn, node, tunnel string, err error) {
	var tunnelID relay.TunnelID
	if h.ingress != nil {
		if rule := h.ingress.GetRule(ctx, host); rule != nil {
			tunnelID = parseTunnelID(rule.Endpoint)
		}
	}

	if tunnelID.IsZero() {
		err = fmt.Errorf("no route to host %s", host)
		res.StatusCode = http.StatusBadGateway
		ro.HTTP.StatusCode = res.StatusCode
		res.Write(conn)
		return
	}

	ro.ClientID = tunnelID.String()

	if tunnelID.IsPrivate() {
		err = fmt.Errorf("access denied: tunnel %s is private for host %s", tunnelID, host)
		res.StatusCode = http.StatusBadGateway
		ro.HTTP.StatusCode = res.StatusCode
		res.Write(conn)
		return
	}

	tunnel = tunnelID.String()

	log = log.WithFields(map[string]any{
		"host":     host,
		"tunnel":   tunnel,
		"clientIP": ro.ClientIP,
	})

	d := &Dialer{
		node:    h.node,
		pool:    h.pool,
		sd:      h.sd,
		retry:   3,
		timeout: 15 * time.Second,
		log:     log,
	}
	cc, node, cid, err := d.Dial(ctx, "tcp", tunnel)
	if err != nil {
		res.Write(conn)
		return
	}
	log.Debugf("new connection to tunnel: %s, connector: %s", tunnel, cid)

	return
}

func (h *entrypoint) httpRoundTrip(ctx context.Context, rw, cc io.ReadWriter, req *http.Request, ro *xrecorder.HandlerRecorderObject, pStats *stats.Stats, log logger.Logger) (close bool, err error) {
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
		if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration": time.Since(ro.Time),
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

	res := &http.Response{
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		StatusCode: http.StatusServiceUnavailable,
	}

	// HTTP/1.0
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		if strings.ToLower(req.Header.Get("Connection")) == "keep-alive" {
			req.Header.Del("Connection")
		} else {
			req.Header.Set("Connection", "close")
		}
	}

	if !h.keepalive {
		req.Header.Set("Connection", "close")
	}

	var reqBody *xhttp.Body
	if opts := h.recorder.Options; opts != nil && opts.HTTPBody {
		if req.Body != nil {
			maxSize := opts.MaxBodySize
			if maxSize <= 0 {
				maxSize = defaultBodySize
			}
			reqBody = xhttp.NewBody(req.Body, maxSize)
			req.Body = reqBody
		}
	}

	if err = req.Write(cc); err != nil {
		log.Errorf("send request: %v", err)
		res.Write(rw)
		return
	}

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	xio.SetReadDeadline(cc, time.Now().Add(h.readTimeout))
	resp, err := http.ReadResponse(bufio.NewReader(cc), req)
	if err != nil {
		log.Errorf("read response: %v", err)
		res.Write(rw)
		return
	}
	defer resp.Body.Close()
	xio.SetReadDeadline(cc, time.Time{})

	ro.HTTP.StatusCode = resp.StatusCode
	ro.HTTP.Response.Header = resp.Header
	ro.HTTP.Response.ContentLength = resp.ContentLength

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
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
	if opts := h.recorder.Options; opts != nil && opts.HTTPBody {
		maxSize := opts.MaxBodySize
		if maxSize <= 0 {
			maxSize = defaultBodySize
		}
		respBody = xhttp.NewBody(resp.Body, maxSize)
		resp.Body = respBody
	}

	if err = resp.Write(rw); err != nil {
		log.Errorf("write response: %v", err)
		return
	}

	if respBody != nil {
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	}

	if req.Header.Get("Upgrade") == "websocket" {
		xnet.Transport(rw, cc)
	}

	return resp.Close, nil
}
