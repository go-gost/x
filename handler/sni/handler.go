package sni

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
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
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	dissector "github.com/go-gost/tls-dissector"
	xbypass "github.com/go-gost/x/bypass"
	ctxvalue "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	netpkg "github.com/go-gost/x/internal/net"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("sni", NewHandler)
}

type sniHandler struct {
	md       metadata
	options  handler.Options
	recorder recorder.RecorderObject
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	h := &sniHandler{
		options: options,
	}

	return h
}

func (h *sniHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandler {
			h.recorder = ro
			break
		}
	}

	return nil
}

func (h *sniHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Network:    "tcp",
		Time:       start,
		SID:        string(ctxvalue.SidFromContext(ctx)),
	}

	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.Duration = time.Since(start)
		ro.Record(ctx, h.recorder.Recorder)

		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return rate_limiter.ErrRateLimit
	}

	var hdr [dissector.RecordHeaderLen]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		log.Error(err)
		return err
	}

	rw := xio.NewReadWriter(io.MultiReader(bytes.NewReader(hdr[:]), conn), conn)

	tlsVersion := binary.BigEndian.Uint16(hdr[1:3])
	if hdr[0] == dissector.Handshake &&
		(tlsVersion >= tls.VersionTLS10 && tlsVersion <= tls.VersionTLS13) {
		return h.handleHTTPS(ctx, rw, conn.RemoteAddr(), ro, log)
	}
	return h.handleHTTP(ctx, rw, conn.RemoteAddr(), ro, log)
}

func (h *sniHandler) handleHTTP(ctx context.Context, rw io.ReadWriter, raddr net.Addr, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	req, err := http.ReadRequest(bufio.NewReader(rw))
	if err != nil {
		return err
	}

	ro.HTTP = &xrecorder.HTTPRecorderObject{
		Host:          req.Host,
		Proto:         req.Proto,
		Scheme:        req.URL.Scheme,
		Method:        req.Method,
		URI:           req.RequestURI,
		RequestHeader: req.Header,
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}

	host := req.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
	}

	ro.Host = req.Host

	log = log.WithFields(map[string]any{
		"host": host,
	})

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, "tcp", host, bypass.WithPathOption(req.RequestURI)) {
		log.Debugf("bypass: %s %s", host, req.RequestURI)
		return xbypass.ErrBypass
	}

	switch h.md.hash {
	case "host":
		ctx = ctxvalue.ContextWithHash(ctx, &ctxvalue.Hash{Source: host})
	}

	cc, err := h.options.Router.Dial(ctx, "tcp", host)
	if err != nil {
		log.Error(err)
		return err
	}
	defer cc.Close()

	t := time.Now()
	log.Infof("%s <-> %s", raddr, host)
	defer func() {
		log.WithFields(map[string]any{
			"duration": time.Since(t),
		}).Infof("%s >-< %s", raddr, host)
	}()

	if err := req.Write(cc); err != nil {
		log.Error(err)
		return err
	}

	br := bufio.NewReader(cc)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		log.Error(err)
		return err
	}
	defer resp.Body.Close()

	ro.HTTP.StatusCode = resp.StatusCode
	ro.HTTP.ResponseHeader = resp.Header

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}

	if err := resp.Write(rw); err != nil {
		log.Error(err)
		return err
	}

	netpkg.Transport(rw, xio.NewReadWriter(br, cc))

	return nil
}

func (h *sniHandler) handleHTTPS(ctx context.Context, rw io.ReadWriter, raddr net.Addr, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	buf := new(bytes.Buffer)
	host, err := h.decodeHost(io.TeeReader(rw, buf))
	if err != nil {
		log.Error(err)
		return err
	}

	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "443")
	}

	ro.Host = host

	log = log.WithFields(map[string]any{
		"dst": host,
	})
	log.Debugf("%s >> %s", raddr, host)

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, "tcp", host) {
		log.Debug("bypass: ", host)
		return xbypass.ErrBypass
	}

	switch h.md.hash {
	case "host":
		ctx = ctxvalue.ContextWithHash(ctx, &ctxvalue.Hash{Source: host})
	}

	cc, err := h.options.Router.Dial(ctx, "tcp", host)
	if err != nil {
		log.Error(err)
		return err
	}
	defer cc.Close()

	t := time.Now()
	log.Infof("%s <-> %s", raddr, host)
	netpkg.Transport(xio.NewReadWriter(io.MultiReader(buf, rw), rw), cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", raddr, host)

	return nil
}

func (h *sniHandler) decodeHost(r io.Reader) (host string, err error) {
	record, err := dissector.ReadRecord(r)
	if err != nil {
		return
	}
	clientHello := dissector.ClientHelloMsg{}
	if err = clientHello.Decode(record.Opaque); err != nil {
		return
	}

	var extensions []dissector.Extension
	for _, ext := range clientHello.Extensions {
		if ext.Type() == 0xFFFE {
			b, _ := ext.Encode()
			if v, err := h.decodeServerName(string(b)); err == nil {
				host = v
			}
			continue
		}
		extensions = append(extensions, ext)
	}
	clientHello.Extensions = extensions

	for _, ext := range clientHello.Extensions {
		if ext.Type() == dissector.ExtServerName {
			snExtension := ext.(*dissector.ServerNameExtension)
			if host == "" {
				host = snExtension.Name
			} else {
				snExtension.Name = host
			}
			break
		}
	}

	return
}

func (h *sniHandler) decodeServerName(s string) (string, error) {
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

func (h *sniHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}
