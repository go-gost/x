package forwarder

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
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	dissector "github.com/go-gost/tls-dissector"
	xbypass "github.com/go-gost/x/bypass"
	"github.com/go-gost/x/config"
	ctxvalue "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	"github.com/go-gost/x/internal/util/sniffing"
	tls_util "github.com/go-gost/x/internal/util/tls"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"golang.org/x/net/http2"
)

const (
	// Default max body size to record.
	DefaultBodySize = 1024 * 1024 // 1MB
)

var (
	DefaultCertPool = tls_util.NewMemoryCertPool()
)

type HandleOptions struct {
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	HTTPKeepalive  bool
	Node           *chain.Node
	Hop            hop.Hop
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

func WithHTTPKeepalive(keepalive bool) HandleOption {
	return func(opts *HandleOptions) {
		opts.HTTPKeepalive = keepalive
	}
}

func WithNode(node *chain.Node) HandleOption {
	return func(opts *HandleOptions) {
		opts.Node = node
	}
}

func WithHop(hop hop.Hop) HandleOption {
	return func(opts *HandleOptions) {
		opts.Hop = hop
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

	pStats := stats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}

	if ho.Log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		ho.Log.Trace(string(dump))
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
	{
		clientAddr := ro.RemoteAddr
		if ro.ClientIP != "" {
			if _, port, _ := net.SplitHostPort(ro.RemoteAddr); port != "" {
				clientAddr = net.JoinHostPort(ro.ClientIP, port)
			}
		}
		ctx = ctxvalue.ContextWithClientAddr(ctx, ctxvalue.ClientAddr(clientAddr))
	}

	// http/2
	if req.Method == "PRI" && len(req.Header) == 0 && req.URL.Path == "*" && req.Proto == "HTTP/2.0" {
		return h.serveH2(ctx, xnet.NewReadWriteConn(br, conn, conn), &ho)
	}

	node, cc, err := h.dial(ctx, conn, req, &ho)
	if err != nil {
		return err
	}
	defer cc.Close()

	log := ho.Log
	log.Debugf("connected to node %s(%s)", node.Name, node.Addr)

	ro.Time = time.Time{}
	shouldClose, err := h.httpRoundTrip(ctx, conn, cc, node, req, &pStats, &ho)
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

		if shouldClose, err := h.httpRoundTrip(ctx, conn, cc, node, req, &pStats, &ho); err != nil || shouldClose {
			return err
		}
	}
}

func (h *Sniffer) dial(ctx context.Context, conn net.Conn, req *http.Request, ho *HandleOptions) (node *chain.Node, cc net.Conn, err error) {
	dial := ho.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	if node = ho.Node; node != nil {
		cc, err = dial(ctx, "tcp", node.Addr)
		return
	}

	ro := ho.RecorderObject

	res := &http.Response{
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Header:     http.Header{},
		StatusCode: http.StatusServiceUnavailable,
	}

	host := req.Host
	if host != "" {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
		}
		ro.Host = host
		ho.Log = ho.Log.WithFields(map[string]any{
			"host": host,
		})

		if ho.Bypass != nil &&
			ho.Bypass.Contains(ctx, "tcp", host, bypass.WithPathOption(req.RequestURI)) {
			ho.Log.Debugf("bypass: %s %s", host, req.RequestURI)
			res.StatusCode = http.StatusForbidden
			ro.HTTP.StatusCode = res.StatusCode
			res.Write(conn)
			return nil, nil, xbypass.ErrBypass
		}
	}

	node = &chain.Node{
		Addr: host,
	}
	if ho.Hop != nil {
		node = ho.Hop.Select(ctx,
			hop.HostSelectOption(host),
			hop.ProtocolSelectOption(sniffing.ProtoHTTP),
			hop.PathSelectOption(req.URL.Path),
		)
	}
	if node == nil {
		ho.Log.Warnf("node for %s not found", host)
		res.StatusCode = http.StatusBadGateway
		ro.HTTP.StatusCode = res.StatusCode
		res.Write(conn)
		return nil, nil, errors.New("node not available")
	}

	ro.Host = node.Addr
	ho.Log = ho.Log.WithFields(map[string]any{
		"node": node.Name,
		"dst":  node.Addr,
	})
	ho.Log.Debugf("find node for host %s -> %s(%s)", host, node.Name, node.Addr)

	cc, err = dial(ctx, "tcp", node.Addr)
	if err != nil {
		// TODO: the router itself may be failed due to the failed node in the router,
		// the dead marker may be a wrong operation.
		if marker := node.Marker(); marker != nil {
			marker.Mark()
		}
		ho.Log.Warnf("connect to node %s(%s) failed: %v", node.Name, node.Addr, err)
		res.Write(conn)
		return
	}
	if marker := node.Marker(); marker != nil {
		marker.Reset()
	}

	if tlsSettings := node.Options().TLS; tlsSettings != nil {
		cfg := &tls.Config{
			ServerName:         tlsSettings.ServerName,
			InsecureSkipVerify: !tlsSettings.Secure,
		}
		tls_util.SetTLSOptions(cfg, &config.TLSOptions{
			MinVersion:   tlsSettings.Options.MinVersion,
			MaxVersion:   tlsSettings.Options.MaxVersion,
			CipherSuites: tlsSettings.Options.CipherSuites,
			ALPN:         tlsSettings.Options.ALPN,
		})
		cc = tls.Client(cc, cfg)
	}
	return
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
			node, cc, err := h.dialTLS(ctx, addr, ho)
			if err != nil {
				return nil, err
			}
			ho.Log.Debugf("connected to node %s(%s)", node.Name, node.Addr)
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

func (h *Sniffer) httpRoundTrip(ctx context.Context, rw, cc io.ReadWriter, node *chain.Node, req *http.Request, pStats *stats.Stats, ho *HandleOptions) (close bool, err error) {
	close = true

	log := ho.Log
	ro := &xrecorder.HandlerRecorderObject{}
	*ro = *ho.RecorderObject

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

	if !ho.HTTPKeepalive {
		req.Header.Set("Connection", "close")
	}

	var bodyRewrites []chain.HTTPBodyRewriteSettings
	if httpSettings := node.Options().HTTP; httpSettings != nil {
		if auther := httpSettings.Auther; auther != nil {
			username, password, _ := req.BasicAuth()
			id, ok := auther.Authenticate(ctx, username, password)
			if !ok {
				res.StatusCode = http.StatusUnauthorized
				ro.HTTP.StatusCode = res.StatusCode
				res.Header.Set("WWW-Authenticate", "Basic")
				log.Warnf("node %s(%s) 401 unauthorized", node.Name, node.Addr)
				res.Write(rw)
				err = errors.New("unauthorized")
				return
			}
			ctx = ctxvalue.ContextWithClientID(ctx, ctxvalue.ClientID(id))
		}

		if httpSettings.Host != "" {
			req.Host = httpSettings.Host
		}
		for k, v := range httpSettings.Header {
			req.Header.Set(k, v)
		}

		for _, re := range httpSettings.RewriteURL {
			if re.Pattern.MatchString(req.URL.Path) {
				if s := re.Pattern.ReplaceAllString(req.URL.Path, re.Replacement); s != "" {
					req.URL.Path = s
					break
				}
			}
		}

		bodyRewrites = httpSettings.RewriteBody
	}

	var reqBody *xhttp.Body
	if opts := h.RecorderOptions; opts != nil && opts.HTTPBody {
		if req.Body != nil {
			maxSize := opts.MaxBodySize
			if maxSize <= 0 {
				maxSize = DefaultBodySize
			}
			reqBody = xhttp.NewBody(req.Body, maxSize)
			req.Body = reqBody
		}
	}

	if err = req.Write(cc); err != nil {
		res.Write(rw)
		return
	}

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	xio.SetReadDeadline(cc, time.Now().Add(h.ReadTimeout))
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

	if err = h.rewriteBody(resp, bodyRewrites...); err != nil {
		log.Errorf("rewrite body: %v", err)
		return
	}

	var respBody *xhttp.Body
	if opts := h.RecorderOptions; opts != nil && opts.HTTPBody {
		maxSize := opts.MaxBodySize
		if maxSize <= 0 {
			maxSize = DefaultBodySize
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

func (h *Sniffer) rewriteBody(resp *http.Response, rewrites ...chain.HTTPBodyRewriteSettings) error {
	if resp == nil || len(rewrites) == 0 || resp.ContentLength <= 0 {
		return nil
	}

	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" {
		return nil
	}

	body, err := drainBody(resp.Body)
	if err != nil || body == nil {
		return err
	}

	contentType, _, _ := strings.Cut(resp.Header.Get("Content-Type"), ";")
	for _, rewrite := range rewrites {
		rewriteType := rewrite.Type
		if rewriteType == "" {
			rewriteType = "text/html"
		}
		if rewriteType != "*" && !strings.Contains(rewriteType, contentType) {
			continue
		}

		body = rewrite.Pattern.ReplaceAll(body, rewrite.Replacement)
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))

	return nil
}

func drainBody(b io.ReadCloser) (body []byte, err error) {
	if b == nil || b == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return nil, nil
	}
	var buf bytes.Buffer
	if _, err = buf.ReadFrom(b); err != nil {
		return nil, err
	}
	if err = b.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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

	node, cc, err := h.dialTLS(ctx, host, &ho)
	if err != nil {
		return err
	}
	defer cc.Close()
	ho.Node = node

	log := ho.Log
	log.Debugf("connected to node %s(%s)", node.Name, node.Addr)

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

func (h *Sniffer) dialTLS(ctx context.Context, host string, ho *HandleOptions) (node *chain.Node, cc net.Conn, err error) {
	dial := ho.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	if node = ho.Node; node != nil {
		cc, err = dial(ctx, "tcp", node.Addr)
		return
	}

	if host != "" {
		node = &chain.Node{
			Addr: host,
		}
	}
	if ho.Hop != nil {
		node = ho.Hop.Select(ctx,
			hop.HostSelectOption(host),
			hop.ProtocolSelectOption(sniffing.ProtoTLS),
		)
	}
	if node == nil {
		err = errors.New("node not available")
		return
	}

	ro := ho.RecorderObject
	addr := node.Addr
	if opts := node.Options(); opts != nil {
		switch opts.Network {
		case "unix":
			ro.Network = opts.Network
		default:
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr += ":443"
			}
		}
	}
	ro.Host = addr

	ho.Log = ho.Log.WithFields(map[string]any{
		"host": host,
		"node": node.Name,
		"dst":  fmt.Sprintf("%s/%s", addr, ro.Network),
	})
	ho.Log.Debugf("find node for host %s -> %s(%s)", host, node.Name, addr)

	cc, err = dial(ctx, ro.Network, addr)
	if err != nil {
		// TODO: the router itself may be failed due to the failed node in the router,
		// the dead marker may be a wrong operation.
		if marker := node.Marker(); marker != nil {
			marker.Mark()
		}
		ho.Log.Warnf("connect to node %s(%s) failed: %v", node.Name, node.Addr, err)
		return
	}

	if marker := node.Marker(); marker != nil {
		marker.Reset()
	}

	if tlsSettings := node.Options().TLS; tlsSettings != nil {
		cfg := &tls.Config{
			ServerName:         tlsSettings.ServerName,
			InsecureSkipVerify: !tlsSettings.Secure,
		}
		tls_util.SetTLSOptions(cfg, &config.TLSOptions{
			MinVersion:   tlsSettings.Options.MinVersion,
			MaxVersion:   tlsSettings.Options.MaxVersion,
			CipherSuites: tlsSettings.Options.CipherSuites,
			ALPN:         tlsSettings.Options.ALPN,
		})
		cc = tls.Client(cc, cfg)
	}
	return
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
		WithHTTPKeepalive(true),
		WithNode(ho.Node),
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
			maxSize := opts.MaxBodySize
			if maxSize <= 0 {
				maxSize = DefaultBodySize
			}
			reqBody = xhttp.NewBody(req.Body, maxSize)
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
		maxSize := opts.MaxBodySize
		if maxSize <= 0 {
			maxSize = DefaultBodySize
		}
		respBody = xhttp.NewBody(resp.Body, maxSize)
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
