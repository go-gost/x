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
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	dissector "github.com/go-gost/tls-dissector"
	xio "github.com/go-gost/x/internal/io"
	netpkg "github.com/go-gost/x/internal/net"
	sx "github.com/go-gost/x/internal/util/selector"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("sni", NewHandler)
}

type sniHandler struct {
	router  *chain.Router
	md      metadata
	options handler.Options
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

	h.router = h.options.Router
	if h.router == nil {
		h.router = chain.NewRouter(chain.LoggerRouterOption(h.options.Logger))
	}

	return nil
}

func (h *sniHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	start := time.Now()
	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return nil
	}

	var hdr [dissector.RecordHeaderLen]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		log.Error(err)
		return err
	}

	rw := xio.NewReadWriter(io.MultiReader(bytes.NewReader(hdr[:]), conn), conn)
	if hdr[0] == dissector.Handshake &&
		binary.BigEndian.Uint16(hdr[1:3]) == tls.VersionTLS10 {
		return h.handleHTTPS(ctx, rw, conn.RemoteAddr(), log)
	}
	return h.handleHTTP(ctx, rw, conn.RemoteAddr(), log)
}

func (h *sniHandler) handleHTTP(ctx context.Context, rw io.ReadWriter, raddr net.Addr, log logger.Logger) error {
	req, err := http.ReadRequest(bufio.NewReader(rw))
	if err != nil {
		return err
	}

	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Trace(string(dump))
	}

	host := req.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "80")
	}
	log = log.WithFields(map[string]any{
		"host": host,
	})

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, host) {
		log.Debug("bypass: ", host)
		return nil
	}

	switch h.md.hash {
	case "host":
		ctx = sx.ContextWithHash(ctx, &sx.Hash{Source: host})
	}

	cc, err := h.router.Dial(ctx, "tcp", host)
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

	var rw2 io.ReadWriter = cc
	if log.IsLevelEnabled(logger.TraceLevel) {
		var buf bytes.Buffer
		resp, err := http.ReadResponse(bufio.NewReader(io.TeeReader(cc, &buf)), req)
		if err != nil {
			log.Error(err)
			return err
		}
		defer resp.Body.Close()

		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))

		rw2 = xio.NewReadWriter(io.MultiReader(&buf, cc), cc)
	}

	netpkg.Transport(rw, rw2)

	return nil
}

func (h *sniHandler) handleHTTPS(ctx context.Context, rw io.ReadWriter, raddr net.Addr, log logger.Logger) error {
	buf := new(bytes.Buffer)
	host, err := h.decodeHost(io.TeeReader(rw, buf))
	if err != nil {
		log.Error(err)
		return err
	}

	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}

	log = log.WithFields(map[string]any{
		"dst": host,
	})
	log.Debugf("%s >> %s", raddr, host)

	if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, host) {
		log.Debug("bypass: ", host)
		return nil
	}

	switch h.md.hash {
	case "host":
		ctx = sx.ContextWithHash(ctx, &sx.Hash{Source: host})
	}

	cc, err := h.router.Dial(ctx, "tcp", host)
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
