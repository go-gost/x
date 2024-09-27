package redirect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	dissector "github.com/go-gost/tls-dissector"
	xbypass "github.com/go-gost/x/bypass"
	ctxvalue "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	netpkg "github.com/go-gost/x/internal/net"
	xhttp "github.com/go-gost/x/internal/net/http"
	tls_util "github.com/go-gost/x/internal/util/tls"
	xrecorder "github.com/go-gost/x/recorder"
)

func (h *redirectHandler) handleHTTP(ctx context.Context, rw io.ReadWriter, dstAddr net.Addr, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	br := bufio.NewReader(rw)
	req, err := http.ReadRequest(br)
	if err != nil {
		return err
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}

	host := req.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
	}
	ro.Host = host

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

	if shoudlClose, err := h.httpRoundTrip(ctx, rw, cc, req, ro, log); err != nil || shoudlClose {
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

		if shouldClose, err := h.httpRoundTrip(ctx, rw, cc, req, ro, log); err != nil || shouldClose {
			return err
		}
	}
}

func (h *redirectHandler) httpRoundTrip(ctx context.Context, rw, cc io.ReadWriter, req *http.Request, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (close bool, err error) {
	close = true

	if req == nil {
		return
	}

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
		return
	}

	if reqBody != nil {
		ro.HTTP.Request.Body = reqBody.Content()
		ro.HTTP.Request.ContentLength = reqBody.Length()
	}

	xio.SetReadDeadline(cc, time.Now().Add(h.md.readTimeout))
	resp, err := http.ReadResponse(bufio.NewReader(cc), req)
	if err != nil {
		log.Errorf("read response: %v", err)
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
		netpkg.Transport(rw, cc)
	}

	return resp.Close, nil
}

func (h *redirectHandler) handleTLS(ctx context.Context, rw io.ReadWriter, dstAddr net.Addr, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
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

	var cc net.Conn

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

	cc.SetReadDeadline(time.Now().Add(h.md.readTimeout))
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

	if _, err := buf.WriteTo(rw); err != nil {
		return err
	}

	t := time.Now()
	log.Infof("%s <-> %s", ro.RemoteAddr, host)
	netpkg.Transport(rw, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", ro.RemoteAddr, host)

	return err
}
