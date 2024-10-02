package remote

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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
	dissector "github.com/go-gost/tls-dissector"
	xbypass "github.com/go-gost/x/bypass"
	"github.com/go-gost/x/config"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/internal/util/sniffing"
	tls_util "github.com/go-gost/x/internal/util/tls"
	xrecorder "github.com/go-gost/x/recorder"
)

const (
	defaultBodySize = 1024 * 1024 // 1MB
)

func (h *forwardHandler) handleHTTP(ctx context.Context, rw io.ReadWriter, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
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

func (h *forwardHandler) httpRoundTrip(ctx context.Context, rw io.ReadWriter, req *http.Request, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (close bool, err error) {
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

	if bp := h.options.Bypass; bp != nil &&
		bp.Contains(ctx, "tcp", host, bypass.WithPathOption(req.RequestURI)) {
		log.Debugf("bypass: %s %s", host, req.RequestURI)
		res.StatusCode = http.StatusForbidden
		ro.HTTP.StatusCode = res.StatusCode
		res.Write(rw)
		err = xbypass.ErrBypass
		return
	}

	target := &chain.Node{
		Addr: host,
	}
	if h.hop != nil {
		target = h.hop.Select(ctx,
			hop.HostSelectOption(host),
			hop.ProtocolSelectOption(sniffing.ProtoHTTP),
			hop.PathSelectOption(req.URL.Path),
		)
	}
	if target == nil {
		log.Warnf("node for %s not found", host)
		res.StatusCode = http.StatusBadGateway
		ro.HTTP.StatusCode = res.StatusCode
		res.Write(rw)
		err = errors.New("node not available")
		return
	}

	ro.Host = target.Addr

	log = log.WithFields(map[string]any{
		"host": req.Host,
		"node": target.Name,
		"dst":  target.Addr,
	})
	log.Debugf("find node for host %s -> %s(%s)", host, target.Name, target.Addr)

	var bodyRewrites []chain.HTTPBodyRewriteSettings
	if httpSettings := target.Options().HTTP; httpSettings != nil {
		if auther := httpSettings.Auther; auther != nil {
			username, password, _ := req.BasicAuth()
			id, ok := auther.Authenticate(ctx, username, password)
			if !ok {
				res.StatusCode = http.StatusUnauthorized
				ro.HTTP.StatusCode = res.StatusCode
				res.Header.Set("WWW-Authenticate", "Basic")
				log.Warnf("node %s(%s) 401 unauthorized", target.Name, target.Addr)
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

	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &buf), "tcp", target.Addr)
	ro.Route = buf.String()
	if err != nil {
		// TODO: the router itself may be failed due to the failed node in the router,
		// the dead marker may be a wrong operation.
		if marker := target.Marker(); marker != nil {
			marker.Mark()
		}
		log.Warnf("connect to node %s(%s) failed: %v", target.Name, target.Addr, err)
		res.Write(rw)
		return
	}
	if marker := target.Marker(); marker != nil {
		marker.Reset()
	}
	// TODO: re-use the connection
	defer cc.Close()

	log.Debugf("connect to node %s(%s)", target.Name, target.Addr)

	if tlsSettings := target.Options().TLS; tlsSettings != nil {
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

	remoteAddr, _ := net.ResolveTCPAddr("tcp", clientAddr)
	localAddr, _ := net.ResolveTCPAddr("tcp", ro.LocalAddr)
	cc = proxyproto.WrapClientConn(h.md.proxyProtocol, remoteAddr, localAddr, cc)

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
		res.Write(rw)
		return
	}

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	cc.SetReadDeadline(time.Now().Add(30 * time.Second))
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

	if err = h.rewriteBody(resp, bodyRewrites...); err != nil {
		log.Errorf("rewrite body: %v", err)
		return
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

func (h *forwardHandler) handleTLS(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	buf := new(bytes.Buffer)

	clientHello, err := dissector.ParseClientHello(io.TeeReader(conn, buf))
	if err != nil {
		return err
	}

	ro.TLS = &xrecorder.TLSRecorderObject{
		ServerName:  clientHello.ServerName,
		ClientHello: hex.EncodeToString(buf.Bytes()),
	}
	if len(clientHello.SupportedProtos) > 0 {
		ro.TLS.Proto = clientHello.SupportedProtos[0]
	}

	host := clientHello.ServerName
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "0")
	}

	var target *chain.Node
	if host != "" {
		target = &chain.Node{
			Addr: host,
		}
	}
	if h.hop != nil {
		target = h.hop.Select(ctx,
			hop.HostSelectOption(host),
			hop.ProtocolSelectOption(sniffing.ProtoTLS),
		)
	}
	if target == nil {
		err := errors.New("target not available")
		log.Error(err)
		return err
	}

	addr := target.Addr
	if opts := target.Options(); opts != nil {
		switch opts.Network {
		case "unix":
			ro.Network = opts.Network
		default:
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr += ":0"
			}
		}
	}
	ro.Host = addr

	log = log.WithFields(map[string]any{
		"host": host,
		"node": target.Name,
		"dst":  fmt.Sprintf("%s/%s", addr, ro.Network),
	})

	log.Debugf("%s >> %s", ro.RemoteAddr, addr)

	var routeBuf bytes.Buffer
	cc, err := h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &routeBuf), ro.Network, addr)
	ro.Route = routeBuf.String()
	if err != nil {
		log.Error(err)
		// TODO: the router itself may be failed due to the failed node in the router,
		// the dead marker may be a wrong operation.
		if marker := target.Marker(); marker != nil {
			marker.Mark()
		}
		return err
	}
	defer cc.Close()
	if marker := target.Marker(); marker != nil {
		marker.Reset()
	}

	if _, err := buf.WriteTo(cc); err != nil {
		return err
	}

	cc.SetReadDeadline(time.Now().Add(30 * time.Second))
	serverHello, err := dissector.ParseServerHello(io.TeeReader(cc, buf))
	cc.SetReadDeadline(time.Time{})

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

	t := time.Now()
	log.Infof("%s <-> %s", ro.RemoteAddr, addr)
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", ro.RemoteAddr, addr)

	return err
}

func (h *forwardHandler) rewriteBody(resp *http.Response, rewrites ...chain.HTTPBodyRewriteSettings) error {
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
