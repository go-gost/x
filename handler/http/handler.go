package http

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
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
	ctx_internal "github.com/go-gost/x/internal/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	"github.com/go-gost/x/internal/util/sniffing"
	stats_util "github.com/go-gost/x/internal/util/stats"
	tls_util "github.com/go-gost/x/internal/util/tls"
	ws_util "github.com/go-gost/x/internal/util/ws"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	cache_limiter "github.com/go-gost/x/limiter/traffic/cache"
	traffic_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/time/rate"
)

func init() {
	registry.HandlerRegistry().Register("http", NewHandler)
}

type httpHandler struct {
	md        metadata
	options   handler.Options
	stats     *stats_util.HandlerStats
	limiter   traffic.TrafficLimiter
	cancel    context.CancelFunc
	recorder  recorder.RecorderObject
	certPool  tls_util.CertPool
	transport http.RoundTripper
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &httpHandler{
		options: options,
	}
}

func (h *httpHandler) Init(md md.Metadata) error {
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

	if h.md.certificate != nil && h.md.privateKey != nil {
		h.certPool = tls_util.NewMemoryCertPool()
	}

	h.transport = &http.Transport{
		DialContext:           h.dial,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: h.md.readTimeout,
		DisableKeepAlives:     !h.md.keepalive,
		DisableCompression:    !h.md.compression,
	}

	return nil
}

func (h *httpHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Proto:      "http",
		Time:       start,
		SID:        string(ctxvalue.SidFromContext(ctx)),
	}

	ro.ClientIP = conn.RemoteAddr().String()
	if clientAddr := ctxvalue.ClientAddrFromContext(ctx); clientAddr != "" {
		ro.ClientIP = string(clientAddr)
	}
	if h, _, _ := net.SplitHostPort(ro.ClientIP); h != "" {
		ro.ClientIP = h
	}

	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
		"client": ro.ClientIP,
	})
	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(start)
		if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
			log.Error("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(start),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return rate_limiter.ErrRateLimit
	}

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Error(err)
		return err
	}
	defer req.Body.Close()

	if clientIP := xhttp.GetClientIP(req); clientIP != nil {
		ro.ClientIP = clientIP.String()
	}

	conn = xnet.NewReadWriteConn(br, conn, conn)

	return h.handleRequest(ctx, conn, req, ro, log)
}

func (h *httpHandler) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	return nil
}

func (h *httpHandler) handleRequest(ctx context.Context, conn net.Conn, req *http.Request, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	if !req.URL.IsAbs() && govalidator.IsDNSName(req.Host) {
		req.URL.Scheme = "http"
	}

	network := req.Header.Get("X-Gost-Protocol")
	if network != "udp" {
		network = "tcp"
	}
	ro.Network = network

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

	addr := req.Host
	if _, port, _ := net.SplitHostPort(addr); port == "" {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), "80")
	}
	ro.Host = addr

	fields := map[string]any{
		"dst":  addr,
		"host": addr,
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
	log.Debugf("%s >> %s", conn.RemoteAddr(), addr)

	resp := &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h.md.header,
		ContentLength: -1,
	}
	if resp.Header == nil {
		resp.Header = http.Header{}
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

	if req.Method == "PRI" ||
		(req.Method != http.MethodConnect && req.URL.Scheme != "http") {
		resp.StatusCode = http.StatusBadRequest

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Trace(string(dump))
		}

		return resp.Write(conn)
	}

	clientID, ok := h.authenticate(ctx, conn, req, resp, log)
	if !ok {
		return errors.New("authentication failed")
	}

	if resp.Header.Get("Proxy-Agent") == "" {
		resp.Header.Set("Proxy-Agent", h.md.proxyAgent)
	}

	ctx = ctxvalue.ContextWithClientID(ctx, ctxvalue.ClientID(clientID))

	if h.options.Bypass != nil &&
		h.options.Bypass.Contains(ctx, network, addr) {
		resp.StatusCode = http.StatusForbidden

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Trace(string(dump))
		}
		log.Debug("bypass: ", addr)
		resp.Write(conn)
		return xbypass.ErrBypass
	}

	if network == "udp" {
		return h.handleUDP(ctx, conn, ro, log)
	}

	{
		rw := traffic_wrapper.WrapReadWriter(
			h.limiter,
			conn,
			clientID,
			limiter.ScopeOption(limiter.ScopeClient),
			limiter.ServiceOption(h.options.Service),
			limiter.NetworkOption(network),
			limiter.AddrOption(addr),
			limiter.ClientOption(clientID),
			limiter.SrcOption(conn.RemoteAddr().String()),
		)
		if h.options.Observer != nil {
			pstats := h.stats.Stats(clientID)
			pstats.Add(stats.KindTotalConns, 1)
			pstats.Add(stats.KindCurrentConns, 1)
			defer pstats.Add(stats.KindCurrentConns, -1)
			rw = stats_wrapper.WrapReadWriter(rw, pstats)
		}

		conn = xnet.NewReadWriteConn(rw, rw, conn)
	}

	if req.Method != http.MethodConnect {
		return h.handleProxy(ctx, conn, req, ro, log)
	}

	ctx = ctx_internal.ContextWithRecorderObject(ctx, ro)
	ctx = ctxvalue.ContextWithLogger(ctx, log)
	cc, err := h.dial(ctx, "tcp", addr)

	if err != nil {
		resp.StatusCode = http.StatusServiceUnavailable

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Trace(string(dump))
		}
		resp.Write(conn)
		return err
	}
	defer cc.Close()

	resp.StatusCode = http.StatusOK
	resp.Status = "200 Connection established"

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}
	if err = resp.Write(conn); err != nil {
		log.Error(err)
		return err
	}

	if h.md.sniffing {
		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(h.md.sniffingTimeout))
		}

		br := bufio.NewReader(conn)
		proto, _ := sniffing.Sniff(ctx, br)
		ro.Proto = proto

		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Time{})
		}

		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			return cc, nil
		}
		dialTLS := func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
			return cc, nil
		}
		sniffer := &sniffing.Sniffer{
			Websocket:           h.md.sniffingWebsocket,
			WebsocketSampleRate: h.md.sniffingWebsocketSampleRate,
			Recorder:            h.recorder.Recorder,
			RecorderOptions:     h.recorder.Options,
			Certificate:         h.md.certificate,
			PrivateKey:          h.md.privateKey,
			NegotiatedProtocol:  h.md.alpn,
			CertPool:            h.certPool,
			MitmBypass:          h.md.mitmBypass,
			ReadTimeout:         h.md.readTimeout,
		}

		conn = xnet.NewReadWriteConn(br, conn, conn)
		switch proto {
		case sniffing.ProtoHTTP:
			return sniffer.HandleHTTP(ctx, conn,
				sniffing.WithDial(dial),
				sniffing.WithDialTLS(dialTLS),
				sniffing.WithRecorderObject(ro),
				sniffing.WithLog(log),
			)
		case sniffing.ProtoTLS:
			return sniffer.HandleTLS(ctx, conn,
				sniffing.WithDial(dial),
				sniffing.WithDialTLS(dialTLS),
				sniffing.WithRecorderObject(ro),
				sniffing.WithLog(log),
			)
		}
	}

	start := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), addr)
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(start),
	}).Infof("%s >-< %s", conn.RemoteAddr(), addr)

	return nil
}

func (h *httpHandler) handleProxy(ctx context.Context, conn net.Conn, req *http.Request, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	ro.Time = time.Time{}

	if close, err := h.proxyRoundTrip(ctx, conn, req, ro, &pStats, log); err != nil || close {
		return err
	}

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

		if close, err := h.proxyRoundTrip(ctx, xio.NewReadWriter(br, conn), req, ro, &pStats, log); err != nil || close {
			return err
		}
	}
}

func (h *httpHandler) proxyRoundTrip(ctx context.Context, rw io.ReadWriter, req *http.Request, ro *xrecorder.HandlerRecorderObject, pStats stats.Stats, log logger.Logger) (close bool, err error) {
	close = true

	ro2 := &xrecorder.HandlerRecorderObject{}
	*ro2 = *ro
	ro = ro2

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
	if clientIP := xhttp.GetClientIP(req); clientIP != nil {
		ro.ClientIP = clientIP.String()
	}

	clientAddr := ro.RemoteAddr
	if ro.ClientIP != "" {
		if _, port, _ := net.SplitHostPort(ro.RemoteAddr); port != "" {
			clientAddr = net.JoinHostPort(ro.ClientIP, port)
		}
	}

	// HTTP/1.0
	http10 := req.ProtoMajor == 1 && req.ProtoMinor == 0
	if http10 {
		if strings.ToLower(req.Header.Get("Connection")) == "keep-alive" {
			req.Header.Del("Connection")
		} else {
			req.Header.Set("Connection", "close")
		}
	}

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
		h.options.Bypass.Contains(ctx, "tcp", host) {
		res.StatusCode = http.StatusForbidden

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(res, false)
			log.Trace(string(dump))
		}
		log.Debug("bypass: ", host)
		res.Write(rw)
		err = xbypass.ErrBypass
		return
	}

	var reqBody *xhttp.Body
	if opts := h.recorder.Options; opts != nil && opts.HTTPBody {
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

	ctx = ctxvalue.ContextWithClientAddr(ctx, ctxvalue.ClientAddr(clientAddr))
	ctx = ctx_internal.ContextWithRecorderObject(ctx, ro)
	ctx = ctxvalue.ContextWithLogger(ctx, log)

	resp, err := h.transport.RoundTrip(req.WithContext(ctx))

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	if err != nil {
		res.Write(rw)
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

	// HTTP/1.0
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

	var respBody *xhttp.Body
	if opts := h.recorder.Options; opts != nil && opts.HTTPBody {
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
		err = fmt.Errorf("write response: %v", err)
		return
	}

	if resp.ContentLength >= 0 {
		close = resp.Close
	}

	return
}

func (h *httpHandler) dial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	switch h.md.hash {
	case "host":
		ctx = ctxvalue.ContextWithHash(ctx, &ctxvalue.Hash{Source: addr})
	}

	if log := ctxvalue.LoggerFromContext(ctx); log != nil {
		log.Debugf("dial: new connection to host %s", addr)
	}

	var buf bytes.Buffer
	conn, err = h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &buf), network, addr)
	if ro := ctx_internal.RecorderObjectFromContext(ctx); ro != nil {
		ro.Route = buf.String()
	}

	return
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

func (h *httpHandler) handleUpgradeResponse(ctx context.Context, rw io.ReadWriter, req *http.Request, res *http.Response, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
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

	return xnet.Transport(rw, backConn)
}

func (h *httpHandler) sniffingWebsocketFrame(ctx context.Context, rw, cc io.ReadWriter, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	errc := make(chan error, 1)

	sampleRate := h.md.sniffingWebsocketSampleRate
	if sampleRate == 0 {
		sampleRate = sniffing.DefaultSampleRate
	}
	if sampleRate < 0 {
		sampleRate = math.MaxFloat64
	}

	go func() {
		ro2 := &xrecorder.HandlerRecorderObject{}
		*ro2 = *ro
		ro := ro2

		limiter := rate.NewLimiter(rate.Limit(sampleRate), int(sampleRate))

		buf := &bytes.Buffer{}
		for {
			start := time.Now()

			if err := h.copyWebsocketFrame(cc, rw, buf, "client", ro); err != nil {
				errc <- err
				return
			}

			if limiter.Allow() {
				ro.Duration = time.Since(start)
				ro.Time = time.Now()
				if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
					log.Errorf("record: %v", err)
				}
			}
		}
	}()

	go func() {
		ro2 := &xrecorder.HandlerRecorderObject{}
		*ro2 = *ro
		ro := ro2

		limiter := rate.NewLimiter(rate.Limit(sampleRate), int(sampleRate))

		buf := &bytes.Buffer{}
		for {
			start := time.Now()

			if err := h.copyWebsocketFrame(rw, cc, buf, "server", ro); err != nil {
				errc <- err
				return
			}

			if limiter.Allow() {
				ro.Duration = time.Since(start)
				ro.Time = time.Now()
				if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
					log.Errorf("record: %v", err)
				}
			}
		}
	}()

	<-errc
	return nil
}

func (h *httpHandler) copyWebsocketFrame(w io.Writer, r io.Reader, buf *bytes.Buffer, from string, ro *xrecorder.HandlerRecorderObject) (err error) {
	fr := ws_util.Frame{}
	if _, err = fr.ReadFrom(r); err != nil {
		return err
	}

	ws := &xrecorder.WebsocketRecorderObject{
		From:    from,
		Fin:     fr.Header.Fin,
		Rsv1:    fr.Header.Rsv1,
		Rsv2:    fr.Header.Rsv2,
		Rsv3:    fr.Header.Rsv3,
		OpCode:  int(fr.Header.OpCode),
		Masked:  fr.Header.Masked,
		MaskKey: fr.Header.MaskKey,
		Length:  fr.Header.PayloadLength,
	}
	if opts := h.recorder.Options; opts != nil && opts.HTTPBody {
		bodySize := opts.MaxBodySize
		if bodySize <= 0 {
			bodySize = sniffing.DefaultBodySize
		}
		if bodySize > sniffing.MaxBodySize {
			bodySize = sniffing.MaxBodySize
		}

		buf.Reset()
		if _, err := io.Copy(buf, io.LimitReader(fr.Data, int64(bodySize))); err != nil {
			return err
		}
		ws.Payload = buf.Bytes()
	}

	ro.Websocket = ws
	length := uint64(fr.Header.Length()) + uint64(fr.Header.PayloadLength)
	if from == "client" {
		ro.InputBytes = length
		ro.OutputBytes = 0
	} else {
		ro.InputBytes = 0
		ro.OutputBytes = length
	}

	fr.Data = io.MultiReader(bytes.NewReader(buf.Bytes()), fr.Data)
	if _, err := fr.WriteTo(w); err != nil {
		return err
	}

	return nil
}

func (h *httpHandler) decodeServerName(s string) (string, error) {
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

func (h *httpHandler) basicProxyAuth(proxyAuth string) (username, password string, ok bool) {
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

func (h *httpHandler) authenticate(ctx context.Context, conn net.Conn, req *http.Request, resp *http.Response, log logger.Logger) (id string, ok bool) {
	u, p, _ := h.basicProxyAuth(req.Header.Get("Proxy-Authorization"))
	if h.options.Auther == nil {
		return "", true
	}
	if id, ok = h.options.Auther.Authenticate(ctx, u, p); ok {
		return
	}

	pr := h.md.probeResistance
	// probing resistance is enabled, and knocking host is mismatch.
	if pr != nil && (pr.Knock == "" || !strings.EqualFold(req.URL.Hostname(), pr.Knock)) {
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

			req.Write(cc)
			xnet.Transport(conn, cc)
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

	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	if resp.StatusCode == 0 {
		realm := defaultRealm
		if h.md.authBasicRealm != "" {
			realm = h.md.authBasicRealm
		}
		resp.StatusCode = http.StatusProxyAuthRequired
		resp.Header.Add("Proxy-Authenticate", fmt.Sprintf("Basic realm=\"%s\"", realm))
		if strings.ToLower(req.Header.Get("Proxy-Connection")) == "keep-alive" {
			// XXX libcurl will keep sending auth request in same conn
			// which we don't supported yet.
			resp.Header.Set("Connection", "close")
			resp.Header.Set("Proxy-Connection", "close")
		}

		log.Debug("proxy authentication required")
	} else {
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

	resp.Write(conn)
	return
}

func (h *httpHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}

func (h *httpHandler) observeStats(ctx context.Context) {
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
