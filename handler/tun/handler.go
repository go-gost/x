package tun

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

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
	dec     DecisionEvaluator
	direct  *directForwarder
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

	if h.options.Logger != nil {
		rt0 := md.Get("tun.relayTarget")
		rt1 := md.Get("relayTarget")
		rt2 := md.Get("relay_target")

		h.options.Logger.WithFields(map[string]any{
			"tun.keepAlivePeriod": h.md.keepAlivePeriod,
			"tun.p2p":             h.md.p2p,
			"tun.relayTarget":     h.md.relayTarget,
			"md.tun.relayTarget":  rt0,
			"md.relayTarget":      rt1,
			"md.relay_target":     rt2,
		}).Debugf("tun metadata parsed")
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
		if dec, ok := md.Get("decisionEvaluator").(DecisionEvaluator); ok {
			h.dec = dec
		}
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

	if h.hop != nil {
		if err := h.handleClient(ctx, conn, config, log); err != nil {
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
