package serial

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	xnet "github.com/go-gost/x/internal/net"
	serial_util "github.com/go-gost/x/internal/util/serial"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
	goserial "github.com/tarm/serial"
)

func init() {
	registry.HandlerRegistry().Register("serial", NewHandler)
}

type serialHandler struct {
	hop      chain.Hop
	router   *chain.Router
	md       metadata
	options  handler.Options
	recorder recorder.Recorder
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

	h.router = h.options.Router
	if h.router == nil {
		h.router = chain.NewRouter(chain.LoggerRouterOption(h.options.Logger))
	}
	if opts := h.router.Options(); opts != nil {
		for _, ro := range opts.Recorders {
			if ro.Record == xrecorder.RecorderServiceHandlerSerial {
				h.recorder = ro.Recorder
				break
			}
		}
	}

	return
}

// Forward implements handler.Forwarder.
func (h *serialHandler) Forward(hop chain.Hop) {
	h.hop = hop
}

func (h *serialHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	log := h.options.Logger

	log = log.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
	})

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

	log.Debugf("%s >> %s", conn.LocalAddr(), target.Addr)

	if h.recorder != nil {
		conn = &recorderConn{
			Conn:     conn,
			recorder: h.recorder,
		}
	}

	// serial port
	if _, _, err := net.SplitHostPort(target.Addr); err != nil {
		return h.forwardSerial(ctx, conn, target, log)
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
	log.Infof("%s <-> %s", conn.LocalAddr(), target.Addr)
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.LocalAddr(), target.Addr)

	return nil
}

func (h *serialHandler) forwardSerial(ctx context.Context, conn net.Conn, target *chain.Node, log logger.Logger) (err error) {
	var port io.ReadWriteCloser

	cfg := serial_util.ParseConfigFromAddr(conn.LocalAddr().String())
	cfg.Name = target.Addr

	if opts := h.router.Options(); opts != nil && opts.Chain != nil {
		port, err = h.router.Dial(ctx, "serial", serial_util.AddrFromConfig(cfg))
	} else {
		cfg.ReadTimeout = h.md.timeout
		port, err = goserial.OpenPort(cfg)
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
