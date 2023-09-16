package com

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/registry"
	goserial "github.com/tarm/serial"
)

func init() {
	registry.HandlerRegistry().Register("com", NewHandler)
}

type comHandler struct {
	hop     chain.Hop
	router  *chain.Router
	md      metadata
	options handler.Options
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &comHandler{
		options: options,
	}
}

func (h *comHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}

	h.router = h.options.Router
	if h.router == nil {
		h.router = chain.NewRouter(chain.LoggerRouterOption(h.options.Logger))
	}

	return
}

// Forward implements handler.Forwarder.
func (h *comHandler) Forward(hop chain.Hop) {
	h.hop = hop
}

func (h *comHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	log := h.options.Logger

	start := time.Now()
	log = log.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	var target *chain.Node
	if h.hop != nil {
		target = h.hop.Select(ctx)
	}

	if target == nil {
		err := errors.New("target not available")
		log.Error(err)
		return err
	}

	log = log.WithFields(map[string]any{
		"node": target.Name,
		"dst":  target.Addr,
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), target.Addr)

	// serial port
	if _, _, err := net.SplitHostPort(target.Addr); err != nil {
		return h.forwardCom(ctx, conn, target, log)
	}

	cc, err := h.router.Dial(ctx, "tcp", target.Addr)
	if err != nil {
		log.Error(err)
		if marker := target.Marker(); marker != nil {
			marker.Mark()
		}
		return err
	}
	defer cc.Close()
	if marker := target.Marker(); marker != nil {
		marker.Reset()
	}

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), target.Addr)
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), target.Addr)

	return nil
}

func (h *comHandler) forwardCom(ctx context.Context, conn net.Conn, target *chain.Node, log logger.Logger) error {
	port, err := goserial.OpenPort(&goserial.Config{
		Name:        target.Addr,
		Baud:        h.md.baudRate,
		Parity:      parseParity(h.md.parity),
		ReadTimeout: h.md.timeout,
	})
	if err != nil {
		return err
	}

	defer port.Close()

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), target.Addr)
	xnet.Transport(conn, port)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), target.Addr)

	return nil
}

func parseParity(s string) goserial.Parity {
	switch strings.ToLower(s) {
	case "o", "odd":
		return goserial.ParityOdd
	case "e", "even":
		return goserial.ParityEven
	case "m", "mark":
		return goserial.ParityMark
	case "s", "space":
		return goserial.ParitySpace
	default:
		return goserial.ParityNone
	}
}
