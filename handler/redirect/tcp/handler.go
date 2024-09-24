package redirect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
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
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	dissector "github.com/go-gost/tls-dissector"
	xbypass "github.com/go-gost/x/bypass"
	ctxvalue "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	netpkg "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	tls_util "github.com/go-gost/x/internal/util/tls"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

const (
	defaultBodySize = 1024 * 1024 // 1MB
)

func init() {
	registry.HandlerRegistry().Register("red", NewHandler)
	registry.HandlerRegistry().Register("redir", NewHandler)
	registry.HandlerRegistry().Register("redirect", NewHandler)
}

type redirectHandler struct {
	md       metadata
	options  handler.Options
	recorder recorder.RecorderObject
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &redirectHandler{
		options: options,
	}
}

func (h *redirectHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandler {
			h.recorder = ro
			break
		}
	}

	return
}

func (h *redirectHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		Network:    "tcp",
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Time:       start,
		SID:        string(ctxvalue.SidFromContext(ctx)),
	}
	ro.ClientIP, _, _ = net.SplitHostPort(conn.RemoteAddr().String())

	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		if !ro.Time.IsZero() {
			if err != nil {
				ro.Err = err.Error()
			}
			ro.Duration = time.Since(start)
			if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
				log.Errorf("record: %v", err)
			}
		}

		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return rate_limiter.ErrRateLimit
	}

	var dstAddr net.Addr

	if h.md.tproxy {
		dstAddr = conn.LocalAddr()
	} else {
		dstAddr, err = h.getOriginalDstAddr(conn)
		if err != nil {
			log.Error(err)
			return
		}
	}

	ro.Host = dstAddr.String()

	log = log.WithFields(map[string]any{
		"dst": fmt.Sprintf("%s/%s", dstAddr, dstAddr.Network()),
	})

	var rw io.ReadWriteCloser = conn
	if h.md.sniffing {
		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(h.md.sniffingTimeout))
		}
		// try to sniff TLS traffic
		var hdr [dissector.RecordHeaderLen]byte
		n, err := io.ReadFull(rw, hdr[:])
		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Time{})
		}
		rw = xio.NewReadWriteCloser(io.MultiReader(bytes.NewReader(hdr[:n]), rw), rw, rw)
		tlsVersion := binary.BigEndian.Uint16(hdr[1:3])
		if err == nil &&
			hdr[0] == dissector.Handshake &&
			(tlsVersion >= tls.VersionTLS10 && tlsVersion <= tls.VersionTLS13) {
			return h.handleHTTPS(ctx, rw, conn.RemoteAddr(), dstAddr, ro, log)
		}

		// try to sniff HTTP traffic
		if isHTTP(string(hdr[:])) {
			ro2 := &xrecorder.HandlerRecorderObject{}
			*ro2 = *ro
			ro.Time = time.Time{}
			return h.handleHTTP(ctx, rw, conn.RemoteAddr(), dstAddr, ro2, log)
		}
	}

	log.Debugf("%s >> %s", conn.RemoteAddr(), dstAddr)

	if h.options.Bypass != nil &&
		h.options.Bypass.Contains(ctx, dstAddr.Network(), dstAddr.String()) {
		log.Debug("bypass: ", dstAddr)
		return xbypass.ErrBypass
	}

	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &buf), dstAddr.Network(), dstAddr.String())
	ro.Route = buf.String()
	if err != nil {
		log.Error(err)
		return err
	}
	defer cc.Close()

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), dstAddr)
	netpkg.Transport(rw, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), dstAddr)

	return nil
}

func (h *redirectHandler) handleHTTP(ctx context.Context, rw io.ReadWriteCloser, raddr, dstAddr net.Addr, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	br := bufio.NewReader(rw)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}

	ro.Host = req.Host
	host := req.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
	}
	log = log.WithFields(map[string]any{
		"host": host,
	})

	if h.options.Bypass != nil &&
		h.options.Bypass.Contains(ctx, "tcp", host, bypass.WithPathOption(req.RequestURI)) {
		log.Debugf("bypass: %s %s", host, req.RequestURI)
		return xbypass.ErrBypass
	}

	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &buf), "tcp", host)
	ro.Route = buf.String()
	if err != nil {
		log.Error(err)
		if !h.md.sniffingFallback {
			return err
		}
	}

	if cc == nil {
		var buf bytes.Buffer
		cc, err = h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &buf), "tcp", dstAddr.String())
		ro.Route = buf.String()
		if err != nil {
			log.Error(err)
			return err
		}
	}
	defer cc.Close()

	if req.Header.Get("Upgrade") == "websocket" {
		return h.handleWebsocket(ctx, raddr, rw, cc, req, ro, log)
	}

	if err := h.httpRoundTrip(ctx, raddr, rw, cc, req, ro, log); err != nil {
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

		if err = h.httpRoundTrip(ctx, raddr, rw, cc, req, ro, log); err != nil {
			return err
		}
	}
}

func (h *redirectHandler) handleWebsocket(ctx context.Context, raddr net.Addr, rw io.ReadWriteCloser, cc io.ReadWriter, req *http.Request, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (err error) {
	start := time.Now()
	ro.Time = start

	log.Infof("%s <-> %s", raddr, req.Host)

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
		}).Infof("%s >-< %s", raddr, req.Host)
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

	if err = req.Write(cc); err != nil {
		return
	}

	res, err := http.ReadResponse(bufio.NewReader(cc), req)
	if err != nil {
		return
	}
	defer res.Body.Close()

	ro.HTTP.StatusCode = res.StatusCode
	ro.HTTP.Response.Header = res.Header
	ro.HTTP.Response.ContentLength = res.ContentLength

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(res, false)
		log.Trace(string(dump))
	}

	if err = res.Write(rw); err != nil {
		return
	}

	netpkg.Transport(rw, cc)

	return
}

func (h *redirectHandler) httpRoundTrip(ctx context.Context, raddr net.Addr, rw io.ReadWriteCloser, cc io.ReadWriter, req *http.Request, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (err error) {
	if req == nil {
		return nil
	}

	start := time.Now()
	ro.Time = start

	log.Infof("%s <-> %s", raddr, req.Host)
	defer func() {
		if err != nil {
			ro.Duration = time.Since(start)
			ro.Err = err.Error()
			if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
				log.Errorf("record: %v", err)
			}

			log.WithFields(map[string]any{
				"duration": time.Since(start),
			}).Infof("%s >-< %s", raddr, req.Host)
		}
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
		return err
	}

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	go func() {
		var err error
		var res *http.Response
		var respBody *xhttp.Body

		defer func() {
			ro.Duration = time.Since(start)
			if err != nil {
				ro.Err = err.Error()
			}
			if res != nil {
				ro.HTTP.StatusCode = res.StatusCode
				ro.HTTP.Response.Header = res.Header
				ro.HTTP.Response.ContentLength = res.ContentLength
				if respBody != nil {
					ro.HTTP.Response.Body = respBody.Content()
					ro.HTTP.Response.ContentLength = respBody.Length()
				}
			}
			ro.Record(ctx, h.recorder.Recorder)
		}()

		res, err = http.ReadResponse(bufio.NewReader(cc), req)
		if err != nil {
			rw.Close()
			log.Errorf("read response: %v", err)
			return
		}
		defer res.Body.Close()

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(res, false)
			log.Trace(string(dump))
		}

		if res.Close {
			defer rw.Close()
		}

		// HTTP/1.0
		if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
			if !res.Close {
				res.Header.Set("Connection", "keep-alive")
			}
			res.ProtoMajor = req.ProtoMajor
			res.ProtoMinor = req.ProtoMinor
		}

		if opts := h.recorder.Options; opts != nil && opts.HTTPBody {
			maxSize := opts.MaxBodySize
			if maxSize <= 0 {
				maxSize = defaultBodySize
			}
			respBody = xhttp.NewBody(res.Body, maxSize)
			res.Body = respBody
		}

		if err = res.Write(rw); err != nil {
			rw.Close()
			log.Errorf("write response: %v", err)
		}
	}()

	return nil
}

func (h *redirectHandler) handleHTTPS(ctx context.Context, rw io.ReadWriter, raddr, dstAddr net.Addr, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	buf := new(bytes.Buffer)

	clientHello, err := dissector.ParseClientHello(io.TeeReader(rw, buf))
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

	var cc io.ReadWriteCloser

	host := clientHello.ServerName
	if host != "" {
		if _, _, err := net.SplitHostPort(host); err != nil {
			_, port, _ := net.SplitHostPort(dstAddr.String())
			if port == "" {
				port = "443"
			}
			host = net.JoinHostPort(strings.Trim(host, "[]"), port)
		}
		log = log.WithFields(map[string]any{
			"host": host,
		})
		ro.Host = host

		if h.options.Bypass != nil &&
			h.options.Bypass.Contains(ctx, "tcp", host) {
			log.Debug("bypass: ", host)
			return xbypass.ErrBypass
		}

		var routeBuf bytes.Buffer
		cc, err = h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &routeBuf), "tcp", host)
		ro.Route = routeBuf.String()
		if err != nil {
			log.Error(err)

			if !h.md.sniffingFallback {
				return err
			}
		}
	}

	if cc == nil {
		var routeBuf bytes.Buffer
		cc, err = h.options.Router.Dial(ctxvalue.ContextWithBuffer(ctx, &routeBuf), "tcp", dstAddr.String())
		ro.Route = routeBuf.String()
		if err != nil {
			log.Error(err)
			return err
		}
	}
	defer cc.Close()

	if _, err := buf.WriteTo(cc); err != nil {
		return err
	}

	serverHello, err := dissector.ParseServerHello(io.TeeReader(cc, buf))
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

	if _, err := buf.WriteTo(rw); err != nil {
		return err
	}

	t := time.Now()
	log.Infof("%s <-> %s", raddr, host)
	netpkg.Transport(rw, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", raddr, host)

	return err
}

func (h *redirectHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}

func isHTTP(s string) bool {
	return strings.HasPrefix(http.MethodGet, s[:3]) ||
		strings.HasPrefix(http.MethodPost, s[:4]) ||
		strings.HasPrefix(http.MethodPut, s[:3]) ||
		strings.HasPrefix(http.MethodDelete, s) ||
		strings.HasPrefix(http.MethodOptions, s) ||
		strings.HasPrefix(http.MethodPatch, s) ||
		strings.HasPrefix(http.MethodHead, s[:4]) ||
		strings.HasPrefix(http.MethodConnect, s) ||
		strings.HasPrefix(http.MethodTrace, s)
}
