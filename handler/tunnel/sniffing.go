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
	"github.com/go-gost/relay"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	xrecorder "github.com/go-gost/x/recorder"
)

const (
	defaultBodySize = 1024 * 1024 // 1MB
)

func (h *entrypoint) handleHTTP(ctx context.Context, rw io.ReadWriter, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	br := bufio.NewReader(rw)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}

	shouldClose, err := h.httpRoundTrip(ctx, rw, req, ro, log)
	if err != nil || shouldClose {
		return err
	}

	for {
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

		if shouldClose, err := h.httpRoundTrip(ctx, rw, req, ro, log); err != nil || shouldClose {
			return err
		}
	}
}

func (h *entrypoint) httpRoundTrip(ctx context.Context, rw io.ReadWriter, req *http.Request, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (close bool, err error) {
	close = true

	start := time.Now()
	ro.Time = start

	log.Infof("%s <-> %s", ro.RemoteAddr, req.Host)
	defer func() {
		ro.Duration = time.Since(start)
		if err != nil {
			ro.Err = err.Error()
		}
		if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration": time.Since(start),
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
	if clientIP := xhttp.GetClientIP(req); clientIP != nil {
		ro.ClientIP = clientIP.String()
	}
	clientAddr := ro.RemoteAddr
	if ro.ClientIP != "" {
		if _, port, _ := net.SplitHostPort(ro.RemoteAddr); port != "" {
			clientAddr = net.JoinHostPort(ro.ClientIP, port)
		}
		ctx = ctxvalue.ContextWithClientAddr(ctx, ctxvalue.ClientAddr(clientAddr))
	}

	// HTTP/1.0
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		if strings.ToLower(req.Header.Get("Connection")) == "keep-alive" {
			req.Header.Del("Connection")
		} else {
			req.Header.Set("Connection", "close")
		}
	}

	res := &http.Response{
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		StatusCode: http.StatusServiceUnavailable,
	}

	host := req.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
	}

	var tunnelID relay.TunnelID
	if h.ingress != nil {
		if rule := h.ingress.GetRule(ctx, req.Host); rule != nil {
			tunnelID = parseTunnelID(rule.Endpoint)
		}
	}
	if tunnelID.IsZero() {
		err = fmt.Errorf("no route to host %s", req.Host)
		log.Error(err)
		res.StatusCode = http.StatusBadGateway
		ro.HTTP.StatusCode = res.StatusCode
		res.Write(rw)
		return
	}

	ro.ClientID = tunnelID.String()

	if tunnelID.IsPrivate() {
		err = fmt.Errorf("access denied: tunnel %s is private for host %s", tunnelID, req.Host)
		log.Error(err)
		res.StatusCode = http.StatusBadGateway
		ro.HTTP.StatusCode = res.StatusCode
		res.Write(rw)
		return
	}

	log = log.WithFields(map[string]any{
		"host":     req.Host,
		"tunnel":   tunnelID.String(),
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
	cc, node, cid, err := d.Dial(ctx, "tcp", tunnelID.String())
	if err != nil {
		log.Error(err)
		res.Write(rw)
		return
	}
	// TODO: re-use connection
	defer cc.Close()
	log.Debugf("new connection to tunnel: %s, connector: %s", tunnelID, cid)

	if node == h.node {
		var features []relay.Feature
		af := &relay.AddrFeature{}
		af.ParseFrom(clientAddr)
		features = append(features, af) // src address

		af = &relay.AddrFeature{}
		af.ParseFrom(host)
		features = append(features, af) // dst address

		if _, err = (&relay.Response{
			Version:  relay.Version1,
			Status:   relay.StatusOK,
			Features: features,
		}).WriteTo(cc); err != nil {
			log.Error(err)
			res.Write(rw)
			return
		}
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

	cc.SetReadDeadline(time.Now().Add(15 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(cc), req)
	if err != nil {
		log.Errorf("read response: %v", err)
		res.Write(rw)
		return
	}
	defer resp.Body.Close()
	cc.SetReadDeadline(time.Time{})

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
