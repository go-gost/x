package tun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	md "github.com/go-gost/core/metadata"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	tun_util "github.com/go-gost/x/internal/util/tun"
	"github.com/go-gost/x/registry"
)

var (
	ErrTun        = errors.New("tun device error")
	ErrInvalidNet = errors.New("invalid net IP")
)

func init() {
	registry.HandlerRegistry().Register("tun", NewHandler)
}

type tunHandler struct {
	hop     hop.Hop
	routes  sync.Map
	md      metadata
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

// Forward implements handler.Forwarder.
func (h *tunHandler) Forward(hop hop.Hop) {
	h.hop = hop
}

func (h *tunHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	log := h.options.Logger

	var config *tun_util.Config
	if md := ictx.MetadataFromContext(ctx); md != nil {
		config, _ = md.Get("config").(*tun_util.Config)
	}
	if config == nil {
		err := errors.New("tun: wrong connection type")
		log.Error(err)
		return err
	}

	start := time.Now()
	log = log.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    xctx.SidFromContext(ctx).String(),
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
	if target != nil {
		network := "udp"
		if _, _, err := net.SplitHostPort(target.Addr); err != nil {
			network = "ip"
		}

		log = log.WithFields(map[string]any{
			"dst": fmt.Sprintf("%s/%s", target.Addr, network),
		})
		log.Debugf("%s >> %s", conn.RemoteAddr(), target.Addr)

		if err := h.handleClient(ctx, conn, network, target.Addr, config, log); err != nil {
			log.Error(err)
		}
		return nil
	}

	return h.handleServer(ctx, conn, config, log)
}

type tunRouteKey [16]byte

func ipToTunRouteKey(ip net.IP) (key tunRouteKey) {
	copy(key[:], ip.To16())
	return
}
