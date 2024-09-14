package serial

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	ctxvalue "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	serial "github.com/go-gost/x/internal/util/serial"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("serial", NewHandler)
}

type serialHandler struct {
	hop      hop.Hop
	md       metadata
	options  handler.Options
	recorder recorder.RecorderObject
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &serialHandler{
		options: options,
	}
}

func (h *serialHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandlerSerial {
			h.recorder = ro
			break
		}
	}

	return
}

// Forward implements handler.Forwarder.
func (h *serialHandler) Forward(hop hop.Hop) {
	h.hop = hop
}

func (h *serialHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	log := h.options.Logger

	log = log.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
	})

	conn = &recorderConn{
		Conn:     conn,
		recorder: h.recorder,
	}

	if h.hop != nil {
		target := h.hop.Select(ctx)
		if target == nil {
			err := errors.New("target not available")
			log.Error(err)
			return err
		}
		log = log.WithFields(map[string]any{
			"node": target.Name,
			"dst":  target.Addr,
		})
		return h.forwardSerial(ctx, conn, target, log)
	}

	cc, err := h.options.Router.Dial(ctx, "tcp", "@")
	if err != nil {
		log.Error(err)
		return err
	}
	defer cc.Close()

	t := time.Now()
	log.Infof("%s <-> %s", conn.LocalAddr(), "@")
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.LocalAddr(), "@")

	return nil
}

func (h *serialHandler) forwardSerial(ctx context.Context, conn net.Conn, target *chain.Node, log logger.Logger) (err error) {
	log.Debugf("%s >> %s", conn.LocalAddr(), target.Addr)
	var port io.ReadWriteCloser

	cfg := serial.ParseConfigFromAddr(conn.LocalAddr().String())
	cfg.Name = target.Addr

	if opts := h.options.Router.Options(); opts != nil && opts.Chain != nil {
		port, err = h.options.Router.Dial(ctx, "serial", serial.AddrFromConfig(cfg))
	} else {
		cfg.ReadTimeout = h.md.timeout
		port, err = serial.OpenPort(cfg)
	}
	if err != nil {
		log.Error(err)
		return err
	}
	defer port.Close()

	t := time.Now()
	log.Infof("%s <-> %s", conn.LocalAddr(), target.Addr)
	xnet.Transport(conn, port)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.LocalAddr(), target.Addr)

	return nil
}
