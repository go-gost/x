package redirect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
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
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
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
			ro.Record(ctx, h.recorder.Recorder)
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

	var rw io.ReadWriter = conn
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
		rw = xio.NewReadWriter(io.MultiReader(bytes.NewReader(hdr[:n]), rw), rw)
		tlsVersion := binary.BigEndian.Uint16(hdr[1:3])
		if err == nil &&
			hdr[0] == dissector.Handshake &&
			(tlsVersion >= tls.VersionTLS10 && tlsVersion <= tls.VersionTLS13) {
			return h.handleHTTPS(ctx, rw, conn.RemoteAddr(), dstAddr, log)
		}

		// try to sniff HTTP traffic
		if isHTTP(string(hdr[:])) {
			return h.handleHTTP(ctx, rw, conn.RemoteAddr(), dstAddr, ro, log)
		}
	}

	log.Debugf("%s >> %s", conn.RemoteAddr(), dstAddr)

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, dstAddr.Network(), dstAddr.String()) {
		log.Debug("bypass: ", dstAddr)
		return xbypass.ErrBypass
	}

	cc, err := h.options.Router.Dial(ctx, dstAddr.Network(), dstAddr.String())
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

func (h *redirectHandler) handleHTTP(ctx context.Context, rw io.ReadWriter, raddr, dstAddr net.Addr, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
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

	ro.Host = req.Host
	host := req.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(strings.Trim(host, "[]"), "80")
	}
	log = log.WithFields(map[string]any{
		"host": host,
	})

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, "tcp", host, bypass.WithPathOption(req.RequestURI)) {
		log.Debugf("bypass: %s %s", host, req.RequestURI)
		return xbypass.ErrBypass
	}

	cc, err := h.options.Router.Dial(ctx, "tcp", host)
	if err != nil {
		log.Error(err)
		if !h.md.sniffingFallback {
			return err
		}
	}

	if cc == nil {
		cc, err = h.options.Router.Dial(ctx, "tcp", dstAddr.String())
		if err != nil {
			log.Error(err)
			return err
		}
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

func (h *redirectHandler) handleHTTPS(ctx context.Context, rw io.ReadWriter, raddr, dstAddr net.Addr, log logger.Logger) error {
	buf := new(bytes.Buffer)
	host, err := h.getServerName(ctx, io.TeeReader(rw, buf))
	if err != nil {
		log.Error(err)
		return err
	}

	var cc io.ReadWriteCloser

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

		if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, "tcp", host) {
			log.Debug("bypass: ", host)
			return nil
		}

		cc, err = h.options.Router.Dial(ctx, "tcp", host)
		if err != nil {
			log.Error(err)

			if !h.md.sniffingFallback {
				return err
			}
		}
	}

	if cc == nil {
		cc, err = h.options.Router.Dial(ctx, "tcp", dstAddr.String())
		if err != nil {
			log.Error(err)
			return err
		}
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

func (h *redirectHandler) getServerName(_ context.Context, r io.Reader) (host string, err error) {
	record, err := dissector.ReadRecord(r)
	if err != nil {
		return
	}

	clientHello := dissector.ClientHelloMsg{}
	if err = clientHello.Decode(record.Opaque); err != nil {
		return
	}

	for _, ext := range clientHello.Extensions {
		if ext.Type() == dissector.ExtServerName {
			snExtension := ext.(*dissector.ServerNameExtension)
			host = snExtension.Name
			break
		}
	}

	return
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
