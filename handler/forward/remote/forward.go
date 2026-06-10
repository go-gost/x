package remote

import (
	"bytes"
	"context"
	"net"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	mdutil "github.com/go-gost/x/metadata/util"
	xrecorder "github.com/go-gost/x/recorder"
)

// handleRawForwarding performs node selection, dials the target through the
// router, and pipes the raw connection. It is used when sniffing is disabled
// or the protocol was not HTTP/TLS.
func (h *forwardHandler) handleRawForwarding(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger, network, proto string) error {
	target := h.selectTarget(ctx, proto)
	if target == nil {
		log.Error(errNodeNotAvailable)
		return errNodeNotAvailable
	}
	addr := target.Addr
	if opts := target.Options(); opts != nil {
		if opts.Network != "" {
			network = opts.Network
		}
	}
	if network != "unix" {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr += ":0"
		}
	}

	ro.Network = network
	ro.Host = addr

	log = log.WithFields(map[string]any{
		"node":    target.Name,
		"dst":     addr,
		"network": network,
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), addr)

	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), network, addr)
	ro.Route = buf.String()
	if err != nil {
		log.Error(err)
		// TODO: the router itself may be failed due to the failed node in the router,
		// the dead marker may be a wrong operation.
		if marker := target.Marker(); marker != nil {
			marker.Mark()
		}
		return err
	}
	if marker := target.Marker(); marker != nil {
		marker.Reset()
	}
	defer cc.Close()

	cc = proxyproto.WrapClientConn(
		h.md.proxyProtocol,
		xctx.SrcAddrFromContext(ctx),
		xctx.DstAddrFromContext(ctx),
		cc)

	log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), target.Addr)
	if err := xnet.Pipe(ctx, conn, cc, xnet.WithReadTimeout(h.md.idleTimeout)); err != nil {
		log.Debugf("pipe: %v", err)
	}
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), target.Addr)

	return nil
}

// selectTarget picks a forwarding target, preferring the host from context
// metadata when set, then falling back to hop selection.
func (h *forwardHandler) selectTarget(ctx context.Context, proto string) *chain.Node {
	if host := mdutil.GetString(ictx.MetadataFromContext(ctx), "host"); host != "" {
		return &chain.Node{Addr: host}
	}
	if curHop := h.getHop(); curHop != nil {
		return curHop.Select(ctx, hop.ProtocolSelectOption(proto))
	}
	return nil
}
