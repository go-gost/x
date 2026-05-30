package http2

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	xbypass "github.com/go-gost/x/bypass"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	traffic_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
)

// NOTE: there is an issue (golang/go#43989) will cause the client hangs
// when server returns an non-200 status code,
// May be fixed in go1.18.
func (h *http2Handler) roundTrip(ctx context.Context, w http.ResponseWriter, req *http.Request, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	if w == nil || req == nil {
		return nil
	}

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
		port := "80"
		if req.URL.Scheme == "https" || req.TLS != nil {
			port = "443"
		}
		host = net.JoinHostPort(strings.Trim(host, "[]"), port)
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

	resp := &http.Response{
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     http.Header{},
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

	clientID, ok, pipeTo := h.authenticate(ctx, w, req, resp, log)
	if !ok {
		if pipeTo != "" {
			cc, err := net.Dial("tcp", pipeTo)
			if err != nil {
				log.Error(err)
				resp.StatusCode = http.StatusServiceUnavailable
				h.writeResponse(w, resp)
				return ErrAuthFailed
			}
			defer cc.Close()
			h.forwardRequest(w, req, cc)
			return ErrAuthFailed
		}
		return ErrAuthFailed
	}

	log = log.WithFields(map[string]any{"clientID": clientID})
	ro.ClientID = clientID

	ctx = xctx.ContextWithClientID(ctx, xctx.ClientID(clientID))

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, "tcp", host, bypass.WithService(h.options.Service)) {
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

	for k := range h.md.header {
		w.Header().Set(k, h.md.header.Get(k))
	}

	switch h.md.hash {
	case "host":
		ctx = xctx.ContextWithHash(ctx, &xctx.Hash{Source: host})
	}

	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), "tcp", host)
	ro.Route = buf.String()
	if err != nil {
		log.Error(err)
		resp.StatusCode = http.StatusServiceUnavailable
		w.WriteHeader(resp.StatusCode)
		return err
	}
	defer cc.Close()

	log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	if req.Method != http.MethodConnect {
		rw := traffic_wrapper.WrapReadWriter(
			h.limiter,
			cc,
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
		err = h.forwardRequest(w, req, rw)
		if err != nil {
			resp.StatusCode = http.StatusServiceUnavailable
			if werr := h.writeResponse(w, resp); werr != nil {
				log.Error("write error response: ", werr)
			}
		}
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >-< %s", req.RemoteAddr, host)

		return err
	}

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
	// xnet.Transport(rw, cc)
	xnet.Pipe(ctx, xio.NewReadWriteCloser(rw, rw, req.Body), cc, xnet.WithReadTimeout(h.md.idleTimeout))
	log.WithFields(map[string]any{
		"duration": time.Since(start),
	}).Infof("%s >-< %s", req.RemoteAddr, host)
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
