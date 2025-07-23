package tun

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/core/handler"
	md "github.com/go-gost/core/metadata"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/registry"
	"github.com/xjasonlyu/tun2socks/v2/core"
)

func init() {
	registry.HandlerRegistry().Register("vtun", NewHandler)
}

type tunHandler struct {
	options handler.Options
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &tunHandler{
		options: options,
	}
}

func (h *tunHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}

	return
}

func (h *tunHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	log := h.options.Logger

	start := time.Now()
	log = log.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	ep, err := newEndpoint(conn, 1420, 0, log)
	if err != nil {
		return err
	}

	th := newTransportHandler(log)
	th.ProcessAsync()
	defer th.Close()

	stack, err := core.CreateStack(&core.Config{
		LinkEndpoint:     ep,
		TransportHandler: th,
	})
	if err != nil {
		return err
	}
	defer stack.Close()

	log.Debugf("is attached: %v", ep.IsAttached())

	<-ctx.Done()

	return nil
}
