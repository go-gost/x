package sniffing

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	dissector "github.com/go-gost/tls-dissector"
	xbypass "github.com/go-gost/x/bypass"
	ctxvalue "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	tls_util "github.com/go-gost/x/internal/util/tls"
	ws_util "github.com/go-gost/x/internal/util/ws"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
)

const (
	// DefaultBodySize is the default HTTP body or websocket frame size to record.
	DefaultBodySize = 64 * 1024 // 64KB
	// MaxBodySize is the maximum HTTP body or websocket frame size to record.
	MaxBodySize = 1024 * 1024 // 1MB
	// DeafultSampleRate is the default websocket sample rate (samples per second).
	DefaultSampleRate = 10.0
)

var (
	DefaultCertPool = tls_util.NewMemoryCertPool()
)

type HandleOptions struct {
	Dial    func(ctx context.Context, network, address string) (net.Conn, error)
	DialTLS func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error)

	Bypass         bypass.Bypass
	RecorderObject *xrecorder.HandlerRecorderObject
	Log            logger.Logger
}

type HandleOption func(opts *HandleOptions)

func WithDial(dial func(ctx context.Context, network, address string) (net.Conn, error)) HandleOption {
	return func(opts *HandleOptions) {
		opts.Dial = dial
	}
}

func WithDialTLS(dialTLS func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error)) HandleOption {
	return func(opts *HandleOptions) {
		opts.DialTLS = dialTLS
	}
}

func WithBypass(bypass bypass.Bypass) HandleOption {
	return func(opts *HandleOptions) {
		opts.Bypass = bypass
	}
}

func WithRecorderObject(ro *xrecorder.HandlerRecorderObject) HandleOption {
	return func(opts *HandleOptions) {
		opts.RecorderObject = ro
	}
}

func WithLog(log logger.Logger) HandleOption {
	return func(opts *HandleOptions) {
		opts.Log = log
	}
}

type Sniffer struct {
	Websocket           bool
	WebsocketSampleRate float64

	Recorder        recorder.Recorder
	RecorderOptions *recorder.Options

	// MITM TLS termination
	Certificate        *x509.Certificate
	PrivateKey         crypto.PrivateKey
	NegotiatedProtocol string
	CertPool           tls_util.CertPool
	MitmBypass         bypass.Bypass

	ReadTimeout time.Duration
}

func (h *Sniffer) HandleHTTP(ctx context.Context, conn net.Conn, opts ...HandleOption) error {
	var ho HandleOptions
	for _, opt := range opts {
		opt(&ho)
	}

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}

	log := ho.Log
	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}

	ro := ho.RecorderObject
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

	// http/2
	if req.Method == "PRI" && len(req.Header) == 0 && req.URL.Path == "*" && req.Proto == "HTTP/2.0" {
		return h.serveH2(ctx, xnet.NewReadWriteConn(br, conn, conn), &ho)
	}

	host := req.Host
	if host != "" {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
		}
		ro.Host = host

		log = log.WithFields(map[string]any{
			"host": host,
		})

		if ho.Bypass != nil && ho.Bypass.Contains(ctx, "tcp", host) {
			return xbypass.ErrBypass
		}
	}

	dial := ho.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	cc, err := dial(ctx, "tcp", host)
	if err != nil {
		return err
	}
	defer cc.Close()

	ro.Time = time.Time{}

	shouldClose, err := h.httpRoundTrip(ctx, xio.NewReadWriter(br, conn), cc, req, ro, &pStats, log)
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

		if shouldClose, err := h.httpRoundTrip(ctx, xio.NewReadWriter(br, conn), cc, req, ro, &pStats, log); err != nil || shouldClose {
			return err
		}
	}
}

func (h *Sniffer) serveH2(ctx context.Context, conn net.Conn, ho *HandleOptions) error {
	const expectedBody = "SM\r\n\r\n"

	buf := make([]byte, len(expectedBody))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		return fmt.Errorf("h2: error reading client preface: %s", err)
	}
	if string(buf[:n]) != expectedBody {
		return errors.New("h2: invalid client preface")
	}

	ro := ho.RecorderObject
	log := ho.Log

	ro.Time = time.Time{}

	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			if dial := ho.DialTLS; dial != nil {
				return dial(ctx, network, addr, cfg)
			}

			cc, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			cc = tls.Client(cc, cfg)
			return cc, nil
		},
	}
	defer tr.CloseIdleConnections()

	(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
		Context:          ctx,
		SawClientPreface: true,
		Handler: &h2Handler{
			transport:       tr,
			recorder:        h.Recorder,
			recorderOptions: h.RecorderOptions,
			recorderObject:  ro,
			log:             log,
		},
	})
	return nil
}

func (h *Sniffer) httpRoundTrip(ctx context.Context, rw, cc io.ReadWriter, req *http.Request, ro *xrecorder.HandlerRecorderObject, pStats stats.Stats, log logger.Logger) (close bool, err error) {
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
		if err := ro.Record(ctx, h.Recorder); err != nil {
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

	// HTTP/1.0
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		if strings.ToLower(req.Header.Get("Connection")) == "keep-alive" {
			req.Header.Del("Connection")
		} else {
			req.Header.Set("Connection", "close")
		}
	}

	var reqBody *xhttp.Body
	if opts := h.RecorderOptions; opts != nil && opts.HTTPBody {
		if req.Body != nil {
			bodySize := opts.MaxBodySize
			if bodySize <= 0 {
				bodySize = DefaultBodySize
			}
			if bodySize > MaxBodySize {
				bodySize = MaxBodySize
			}
			reqBody = xhttp.NewBody(req.Body, bodySize)
			req.Body = reqBody
		}
	}

	err = req.Write(cc)

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	if err != nil {
		return
	}

	xio.SetReadDeadline(cc, time.Now().Add(h.ReadTimeout))
	resp, err := http.ReadResponse(bufio.NewReader(cc), req)
	if err != nil {
		err = fmt.Errorf("read response: %w", err)
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
	if opts := h.RecorderOptions; opts != nil && opts.HTTPBody {
		bodySize := opts.MaxBodySize
		if bodySize <= 0 {
			bodySize = DefaultBodySize
		}
		if bodySize > MaxBodySize {
			bodySize = MaxBodySize
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
		err = fmt.Errorf("write response: %w", err)
		return
	}

	if resp.ContentLength >= 0 {
		close = resp.Close
	}

	return
}

func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

func (h *Sniffer) handleUpgradeResponse(ctx context.Context, rw io.ReadWriter, cc io.ReadWriter, req *http.Request, res *http.Response, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	reqUpType := upgradeType(req.Header)
	resUpType := upgradeType(res.Header)
	if !strings.EqualFold(reqUpType, resUpType) {
		return fmt.Errorf("backend tried to switch protocol %q when %q was requested", resUpType, reqUpType)
	}

	res.Body = nil
	if err := res.Write(rw); err != nil {
		return fmt.Errorf("response write: %v", err)
	}

	if reqUpType == "websocket" && h.Websocket {
		return h.sniffingWebsocketFrame(ctx, rw, cc, ro, log)
	}

	return xnet.Transport(rw, cc)
}

func (h *Sniffer) sniffingWebsocketFrame(ctx context.Context, rw, cc io.ReadWriter, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	errc := make(chan error, 1)

	sampleRate := h.WebsocketSampleRate
	if sampleRate == 0 {
		sampleRate = DefaultSampleRate
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
				if err := ro.Record(ctx, h.Recorder); err != nil {
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
				if err := ro.Record(ctx, h.Recorder); err != nil {
					log.Errorf("record: %v", err)
				}
			}
		}
	}()

	<-errc
	return nil
}

func (h *Sniffer) copyWebsocketFrame(w io.Writer, r io.Reader, buf *bytes.Buffer, from string, ro *xrecorder.HandlerRecorderObject) (err error) {
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
	if opts := h.RecorderOptions; opts != nil && opts.HTTPBody {
		bodySize := opts.MaxBodySize
		if bodySize <= 0 {
			bodySize = DefaultBodySize
		}
		if bodySize > MaxBodySize {
			bodySize = MaxBodySize
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

func (h *Sniffer) HandleTLS(ctx context.Context, conn net.Conn, opts ...HandleOption) error {
	var ho HandleOptions
	for _, opt := range opts {
		opt(&ho)
	}

	buf := new(bytes.Buffer)
	clientHello, err := dissector.ParseClientHello(io.TeeReader(conn, buf))
	if err != nil {
		return err
	}

	log := ho.Log

	ro := ho.RecorderObject
	ro.TLS = &xrecorder.TLSRecorderObject{
		ServerName:  clientHello.ServerName,
		ClientHello: hex.EncodeToString(buf.Bytes()),
	}
	if len(clientHello.SupportedProtos) > 0 {
		ro.TLS.Proto = clientHello.SupportedProtos[0]
	}

	ctx = ctxvalue.ContextWithClientAddr(ctx, ctxvalue.ClientAddr(ro.RemoteAddr))

	host := clientHello.ServerName
	if host != "" {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), "443")
		}
		ro.Host = host

		if ho.Bypass != nil && ho.Bypass.Contains(ctx, "tcp", host) {
			return xbypass.ErrBypass
		}
	}

	dial := ho.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	cc, err := dial(ctx, "tcp", host)
	if err != nil {
		return err
	}
	defer cc.Close()

	if h.Certificate != nil && h.PrivateKey != nil &&
		len(clientHello.SupportedProtos) > 0 && (clientHello.SupportedProtos[0] == "h2" || clientHello.SupportedProtos[0] == "http/1.1") {
		if host == "" {
			host = ro.Host
		}
		if h.MitmBypass == nil || !h.MitmBypass.Contains(ctx, "tcp", host) {
			return h.terminateTLS(ctx, xnet.NewReadWriteConn(io.MultiReader(buf, conn), conn, conn), cc, clientHello, &ho)
		}
	}

	if _, err := buf.WriteTo(cc); err != nil {
		return err
	}

	xio.SetReadDeadline(cc, time.Now().Add(h.ReadTimeout))
	serverHello, err := dissector.ParseServerHello(io.TeeReader(cc, buf))
	xio.SetReadDeadline(cc, time.Time{})

	if serverHello != nil {
		ro.TLS.CipherSuite = tls_util.CipherSuite(serverHello.CipherSuite).String()
		ro.TLS.CompressionMethod = serverHello.CompressionMethod
		if serverHello.Proto != "" {
			ro.TLS.Proto = serverHello.Proto
		}
		if serverHello.Version > 0 {
			ro.TLS.Version = tls_util.Version(serverHello.Version).String()
		}
	}

	if buf.Len() > 0 {
		ro.TLS.ServerHello = hex.EncodeToString(buf.Bytes())
	}

	if _, err := buf.WriteTo(conn); err != nil {
		return err
	}

	log.Infof("%s <-> %s", ro.RemoteAddr, ro.Host)
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(ro.Time),
	}).Infof("%s >-< %s", ro.RemoteAddr, ro.Host)

	return err
}

func (h *Sniffer) terminateTLS(ctx context.Context, conn, cc net.Conn, clientHello *dissector.ClientHelloInfo, ho *HandleOptions) error {
	ro := ho.RecorderObject
	log := ho.Log

	nextProtos := clientHello.SupportedProtos
	if h.NegotiatedProtocol != "" {
		nextProtos = []string{h.NegotiatedProtocol}
	}

	cfg := &tls.Config{
		ServerName:   clientHello.ServerName,
		NextProtos:   nextProtos,
		CipherSuites: clientHello.CipherSuites,
	}
	if cfg.ServerName == "" {
		cfg.InsecureSkipVerify = true
	}
	clientConn := tls.Client(cc, cfg)
	if err := clientConn.HandshakeContext(ctx); err != nil {
		return err
	}

	cs := clientConn.ConnectionState()
	ro.TLS.CipherSuite = tls_util.CipherSuite(cs.CipherSuite).String()
	ro.TLS.Proto = cs.NegotiatedProtocol
	ro.TLS.Version = tls_util.Version(cs.Version).String()

	host := cfg.ServerName
	if host == "" {
		if host = cs.PeerCertificates[0].Subject.CommonName; host == "" {
			host = ro.Host
		}
	}
	if h, _, _ := net.SplitHostPort(host); h != "" {
		host = h
	}

	negotiatedProtocol := cs.NegotiatedProtocol
	if h.NegotiatedProtocol != "" {
		negotiatedProtocol = h.NegotiatedProtocol
	}
	nextProtos = nil
	if negotiatedProtocol != "" {
		nextProtos = []string{negotiatedProtocol}
	}

	// cache the tls server handshake record.
	wb := &bytes.Buffer{}
	conn = xnet.NewReadWriteConn(conn, io.MultiWriter(wb, conn), conn)

	serverConn := tls.Server(conn, &tls.Config{
		NextProtos: nextProtos,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certPool := h.CertPool
			if certPool == nil {
				certPool = DefaultCertPool
			}
			serverName := chi.ServerName
			if serverName == "" {
				serverName = host
			}
			cert, err := certPool.Get(serverName)
			if cert != nil {
				pool := x509.NewCertPool()
				pool.AddCert(h.Certificate)
				if _, err = cert.Verify(x509.VerifyOptions{
					DNSName: serverName,
					Roots:   pool,
				}); err != nil {
					log.Warnf("verify cached certificate for %s: %v", serverName, err)
					cert = nil
				}
			}
			if cert == nil {
				cert, err = tls_util.GenerateCertificate(serverName, 7*24*time.Hour, h.Certificate, h.PrivateKey)
				certPool.Put(serverName, cert)
			}
			if err != nil {
				return nil, err
			}

			return &tls.Certificate{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  h.PrivateKey,
			}, nil
		},
	})
	err := serverConn.HandshakeContext(ctx)
	if record, _ := dissector.ReadRecord(wb); record != nil {
		wb.Reset()
		record.WriteTo(wb)
		ro.TLS.ServerHello = hex.EncodeToString(wb.Bytes())
	}
	if err != nil {
		return err
	}

	opts := []HandleOption{
		WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
			return clientConn, nil
		}),
		WithDialTLS(func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
			return clientConn, nil
		}),
		WithRecorderObject(ro),
		WithLog(log),
	}
	return h.HandleHTTP(ctx, serverConn, opts...)
}

type h2Handler struct {
	transport       http.RoundTripper
	recorder        recorder.Recorder
	recorderOptions *recorder.Options
	recorderObject  *xrecorder.HandlerRecorderObject
	log             logger.Logger
}

func (h *h2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := h.log

	ro := &xrecorder.HandlerRecorderObject{}
	*ro = *h.recorderObject
	ro.Time = time.Now()

	var err error
	log.Infof("%s <-> %s", ro.RemoteAddr, r.Host)
	defer func() {
		ro.Duration = time.Since(ro.Time)
		if err != nil {
			ro.Err = err.Error()
		}
		if err := ro.Record(r.Context(), h.recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration": time.Since(ro.Time),
		}).Infof("%s >-< %s", ro.RemoteAddr, r.Host)
	}()

	if clientIP := xhttp.GetClientIP(r); clientIP != nil {
		ro.ClientIP = clientIP.String()
	}
	ro.HTTP = &xrecorder.HTTPRecorderObject{
		Host:   r.Host,
		Proto:  r.Proto,
		Scheme: "https",
		Method: r.Method,
		URI:    r.RequestURI,
		Request: xrecorder.HTTPRequestRecorderObject{
			ContentLength: r.ContentLength,
			Header:        r.Header.Clone(),
		},
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(r, false)
		log.Trace(string(dump))
	}

	url := r.URL
	url.Scheme = "https"
	url.Host = r.Host
	req := &http.Request{
		Method:        r.Method,
		URL:           url,
		Host:          r.Host,
		Header:        r.Header,
		Body:          r.Body,
		ContentLength: r.ContentLength,
		Trailer:       r.Trailer,
	}

	var reqBody *xhttp.Body
	if opts := h.recorderOptions; opts != nil && opts.HTTPBody {
		if req.Body != nil {
			bodySize := opts.MaxBodySize
			if bodySize <= 0 {
				bodySize = DefaultBodySize
			}
			if bodySize > MaxBodySize {
				bodySize = MaxBodySize
			}

			reqBody = xhttp.NewBody(req.Body, bodySize)
			req.Body = reqBody
		}
	}

	resp, err := h.transport.RoundTrip(req.WithContext(r.Context()))
	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	ro.HTTP.StatusCode = resp.StatusCode
	ro.HTTP.Response.Header = resp.Header
	ro.HTTP.Response.ContentLength = resp.ContentLength

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	h.setHeader(w, resp.Header)
	w.WriteHeader(resp.StatusCode)

	var respBody *xhttp.Body
	if opts := h.recorderOptions; opts != nil && opts.HTTPBody {
		bodySize := opts.MaxBodySize
		if bodySize <= 0 {
			bodySize = DefaultBodySize
		}
		if bodySize > MaxBodySize {
			bodySize = MaxBodySize
		}
		respBody = xhttp.NewBody(resp.Body, bodySize)
		resp.Body = respBody
	}

	io.Copy(w, resp.Body)

	if respBody != nil {
		ro.HTTP.Response.Body = respBody.Content()
		ro.HTTP.Response.ContentLength = respBody.Length()
	}
}

func (h *h2Handler) setHeader(w http.ResponseWriter, header http.Header) {
	for k, v := range header {
		for i := range v {
			w.Header().Add(k, v[i])
		}
	}
}
