package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
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
	router  *peerTable
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

	// After parseMetadata, so the table's TTL is the configured keepalive
	// period rather than the zero a pre-parse construction would give it.
	h.router = newPeerTable(h.options.Auther, h.md.keepAlivePeriod, h.options.Service, h.options.Logger)

	return
}

// SetPrefixRoutes replaces the hub's prefix table. Routes are matched
// longest-prefix-first, and only after an exact peerTable match — a member's
// registered /32 is unmatched authority and never displaced by a LAN route.
//
// It is meaningless on a spoke: a spoke routes no inbound peer, so it has no
// delivery decision for a prefix to inform, and the table it would install
// is never consulted.
func (h *tunHandler) SetPrefixRoutes(routes map[netip.Prefix]prefixRoute) {
	h.router.SetPrefixRoutes(routes)
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

	raddr, client := h.selectTarget(ctx)
	if client {
		network := "udp"
		if _, _, err := net.SplitHostPort(raddr); err != nil {
			network = "ip"
		}

		log = log.WithFields(map[string]any{
			"dst": fmt.Sprintf("%s/%s", raddr, network),
		})
		log.Debugf("%s >> %s", conn.RemoteAddr(), raddr)

		if err := h.handleClient(ctx, conn, network, raddr, config, log); err != nil {
			// A device (or connection) closed under the reader is how a stop
			// ends, not a failure: see client.go's read loop. Anything else is
			// a real error.
			if errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
				log.Debug(err)
			} else {
				log.Error(err)
			}
		}
		return nil
	}

	return h.handleServer(ctx, conn, config, log)
}

// selectTarget decides the handler's mode and the address to dial.
//
//   - A forwarder hop (the service `forwarder:` config) selects client mode
//     with the node's address, as before.
//   - Without a forwarder, a chain means client mode with an empty address:
//     the link is transparent (the connector does no dialing of its own) and
//     the peer comes from the chain node instead — a p2p node's addr is its
//     peer key, not a destination.
//   - Neither means server mode.
//
// A chain without a forwarder used to be dead config for this handler (the
// server branch never read it) and is now client mode, so it is logged.
func (h *tunHandler) selectTarget(ctx context.Context) (addr string, client bool) {
	if h.hop != nil {
		if node := h.hop.Select(ctx); node != nil {
			return node.Addr, true
		}
		return "", false
	}
	if h.options.Router != nil {
		if ro := h.options.Router.Options(); ro != nil && ro.Chain != nil {
			h.options.Logger.Warn("tun: chain without forwarder, running in client mode")
			return "", true
		}
	}
	return "", false
}

// collectFirstError drains errc (whose capacity must equal the number of
// goroutines writing to it) and returns the first error that is not io.EOF,
// context.Canceled, or context.DeadlineExceeded. It cancels the derived
// context after the first error to signal sibling goroutines to exit.
// A timeout on the second read prevents deadlock when a goroutine is stuck
// in a blocking read that is not context-aware.
func collectFirstError(errc <-chan error, cancel context.CancelFunc) error {
	var firstErr error
	// Wait for the first goroutine to exit.
	err := <-errc
	cancel() // signal the sibling goroutine to exit
	if err != nil && err != io.EOF && err != context.Canceled && err != context.DeadlineExceeded {
		firstErr = err
	}
	// Wait for the sibling goroutine, but don't block forever — the
	// goroutine may be stuck in a blocking read that is not context-aware.
	select {
	case err := <-errc:
		if err != nil && firstErr == nil && err != io.EOF && err != context.Canceled && err != context.DeadlineExceeded {
			firstErr = err
		}
	case <-time.After(5 * time.Second):
	}
	return firstErr
}

type tunRouteKey [16]byte

func ipToTunRouteKey(ip net.IP) (key tunRouteKey) {
	copy(key[:], ip.To16())
	return
}
