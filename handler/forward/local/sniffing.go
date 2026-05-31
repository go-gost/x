package local

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"net"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/internal/util/forwarder"
	"github.com/go-gost/x/internal/util/sniffing"
	tls_util "github.com/go-gost/x/internal/util/tls"
	xrecorder "github.com/go-gost/x/recorder"
)

// SnifferBuilder holds configuration for creating per-connection protocol sniffers.
// It is populated once during Init and reused for each connection.
type SnifferBuilder struct {
	Websocket           bool
	WebsocketSampleRate float64
	Recorder            recorder.Recorder
	RecorderOptions     *recorder.Options
	Certificate         *x509.Certificate
	PrivateKey          crypto.PrivateKey
	ALPN                string
	CertPool            tls_util.CertPool
	MitmBypass          bypass.Bypass
	// ReadTimeout is the timeout for reading upstream HTTP response headers
	// and TLS ServerHello during sniffing. Passed through to forwarder.Sniffer.
	// See forwarder.Sniffer.ReadTimeout for details.
	ReadTimeout         time.Duration
}

// Build creates a new forwarder.Sniffer from the builder's configuration.
func (b *SnifferBuilder) Build() *forwarder.Sniffer {
	return &forwarder.Sniffer{
		Websocket:           b.Websocket,
		WebsocketSampleRate: b.WebsocketSampleRate,
		Recorder:            b.Recorder,
		RecorderOptions:     b.RecorderOptions,
		Certificate:         b.Certificate,
		PrivateKey:          b.PrivateKey,
		NegotiatedProtocol:  b.ALPN,
		CertPool:            b.CertPool,
		MitmBypass:          b.MitmBypass,
		ReadTimeout:         b.ReadTimeout,
	}
}

// sniffingDial creates a dial function for the sniffing branch that wraps
// Router.Dial with route recording and proxy protocol encapsulation.
func (h *forwardHandler) sniffingDial(ctx context.Context, network, address string, ro *xrecorder.HandlerRecorderObject) (net.Conn, error) {
	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), "tcp", address)
	ro.Route = buf.String()
	return proxyproto.WrapClientConn(
		h.md.proxyProtocol,
		xctx.SrcAddrFromContext(ctx),
		xctx.DstAddrFromContext(ctx),
		cc), err
}

// handleSniffedProtocol dispatches a sniffed connection to the protocol-specific
// sniffer (HandleHTTP or HandleTLS). It returns (true, err) when the protocol was
// handled and (false, nil) when the caller should fall through to raw forwarding.
func (h *forwardHandler) handleSniffedProtocol(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger, proto string) (handled bool, err error) {
	switch proto {
	case sniffing.ProtoHTTP, sniffing.ProtoTLS:
		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			return h.sniffingDial(ctx, network, address, ro)
		}
		sniffer := h.sniffer.Build()
		if proto == sniffing.ProtoHTTP {
			return true, sniffer.HandleHTTP(ctx, conn,
				forwarder.WithService(h.options.Service),
				forwarder.WithDial(dial),
				forwarder.WithHop(h.getHop()),
				forwarder.WithBypass(h.options.Bypass),
				forwarder.WithHTTPKeepalive(h.md.httpKeepalive),
				forwarder.WithRecorderObject(ro),
				forwarder.WithLog(log),
			)
		}
		return true, sniffer.HandleTLS(ctx, conn,
			forwarder.WithService(h.options.Service),
			forwarder.WithDial(dial),
			forwarder.WithHop(h.getHop()),
			forwarder.WithBypass(h.options.Bypass),
			forwarder.WithRecorderObject(ro),
			forwarder.WithLog(log),
		)
	default:
		return false, nil
	}
}
