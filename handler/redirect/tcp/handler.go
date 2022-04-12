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
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	dissector "github.com/go-gost/tls-dissector"
	netpkg "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("red", NewHandler)
	registry.HandlerRegistry().Register("redir", NewHandler)
	registry.HandlerRegistry().Register("redirect", NewHandler)
}

type redirectHandler struct {
	router  *chain.Router
	md      metadata
	options handler.Options
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

	h.router = h.options.Router
	if h.router == nil {
		h.router = (&chain.Router{}).WithLogger(h.options.Logger)
	}

	return
}

func (h *redirectHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
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

	log = log.WithFields(map[string]any{
		"dst": fmt.Sprintf("%s/%s", dstAddr, dstAddr.Network()),
	})

	var rw io.ReadWriter = conn
	if h.md.sniffing {
		// try to sniff TLS traffic
		var hdr [dissector.RecordHeaderLen]byte
		_, err := io.ReadFull(rw, hdr[:])
		rw = &readWriter{
			Reader: io.MultiReader(bytes.NewReader(hdr[:]), rw),
			Writer: rw,
		}
		if err == nil &&
			hdr[0] == dissector.Handshake &&
			binary.BigEndian.Uint16(hdr[1:3]) == tls.VersionTLS10 {
			return h.handleHTTPS(ctx, rw, conn.RemoteAddr(), dstAddr, log)
		}

		// try to sniff HTTP traffic
		buf := new(bytes.Buffer)
		_, err = http.ReadRequest(bufio.NewReader(io.TeeReader(rw, buf)))
		rw = &readWriter{
			Reader: io.MultiReader(buf, rw),
			Writer: rw,
		}
		if err == nil {
			return h.handleHTTP(ctx, rw, conn.RemoteAddr(), log)
		}
	}

	log.Infof("%s >> %s", conn.RemoteAddr(), dstAddr)

	if h.options.Bypass != nil && h.options.Bypass.Contains(dstAddr.String()) {
		log.Info("bypass: ", dstAddr)
		return nil
	}

	cc, err := h.router.Dial(ctx, dstAddr.Network(), dstAddr.String())
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

func (h *redirectHandler) handleHTTP(ctx context.Context, rw io.ReadWriter, raddr net.Addr, log logger.Logger) error {
	req, err := http.ReadRequest(bufio.NewReader(rw))
	if err != nil {
		return err
	}

	if log.IsLevelEnabled(logger.DebugLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		log.Debug(string(dump))
	}

	host := req.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "80")
	}
	log = log.WithFields(map[string]any{
		"host": host,
	})

	if h.options.Bypass != nil && h.options.Bypass.Contains(host) {
		log.Info("bypass: ", host)
		return nil
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

	resp, err := http.ReadResponse(bufio.NewReader(cc), req)
	if err != nil {
		log.Error(err)
		return err
	}
	defer resp.Body.Close()

	if log.IsLevelEnabled(logger.DebugLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Debug(string(dump))
	}

	return resp.Write(rw)
}

func (h *redirectHandler) handleHTTPS(ctx context.Context, rw io.ReadWriter, raddr, dstAddr net.Addr, log logger.Logger) error {
	buf := new(bytes.Buffer)
	host, err := h.getServerName(ctx, io.TeeReader(rw, buf))
	if err != nil {
		log.Error(err)
		return err
	}
	if host == "" {
		host = dstAddr.String()
	} else {
		if _, _, err := net.SplitHostPort(host); err != nil {
			_, port, _ := net.SplitHostPort(dstAddr.String())
			if port == "" {
				port = "443"
			}
			host = net.JoinHostPort(host, port)
		}
	}

	log = log.WithFields(map[string]any{
		"host": host,
	})

	if h.options.Bypass != nil && h.options.Bypass.Contains(host) {
		log.Info("bypass: ", host)
		return nil
	}

	cc, err := h.router.Dial(ctx, "tcp", host)
	if err != nil {
		log.Error(err)
		return err
	}
	defer cc.Close()

	t := time.Now()
	log.Infof("%s <-> %s", raddr, host)
	netpkg.Transport(&readWriter{
		Reader: io.MultiReader(buf, rw),
		Writer: rw,
	}, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", raddr, host)

	return nil
}

func (h *redirectHandler) getServerName(ctx context.Context, r io.Reader) (host string, err error) {
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
