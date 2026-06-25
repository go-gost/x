package sni

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	"github.com/go-gost/x/internal/util/sniffing"
	tls_util "github.com/go-gost/x/internal/util/tls"
	xrecorder "github.com/go-gost/x/recorder"
)

// SnifferBuilder holds configuration for creating per-connection protocol
// sniffers. It is populated once during Init and reused via [SnifferBuilder.Build]
// for each connection to avoid repeated allocation.
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
	// and TLS ServerHello during sniffing. Passed through to [sniffing.Sniffer].
	// See sniffing.Sniffer.ReadTimeout for details.
	ReadTimeout time.Duration
}

// Build creates a new [sniffing.Sniffer] from the builder's configuration.
// Each call produces a fresh instance, safe for per-connection use.
func (b *SnifferBuilder) Build() *sniffing.Sniffer {
	return &sniffing.Sniffer{
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
// [chain.Router.Dial] with context-based hash selection, route recording,
// and source/destination address population for the recorder.
func (h *sniHandler) sniffingDial(ctx context.Context, network, address string, ro *xrecorder.HandlerRecorderObject) (net.Conn, error) {
	switch h.md.hash {
	case "host":
		ctx = xctx.ContextWithHash(ctx, &xctx.Hash{Source: address})
	}

	var buf bytes.Buffer
	cc, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), "tcp", address)
	ro.Route = buf.String()

	if cc != nil {
		ro.SrcAddr = cc.LocalAddr().String()
		ro.DstAddr = cc.RemoteAddr().String()
	}
	return cc, err
}

// sniffingDialTLS creates a TLS-aware dial function for the sniffing branch.
// It dials via [sniffingDial] and wraps the connection with [tls.Client].
func (h *sniHandler) sniffingDialTLS(ctx context.Context, network, address string, ro *xrecorder.HandlerRecorderObject, cfg *tls.Config) (net.Conn, error) {
	cc, err := h.sniffingDial(ctx, network, address, ro)
	if err != nil {
		return nil, err
	}
	return tls.Client(cc, cfg), nil
}

// handleSniffedProtocol dispatches a sniffed connection to the
// protocol-specific sniffer ([sniffing.Sniffer.HandleHTTP] or
// [sniffing.Sniffer.HandleTLS]).
//
// It returns (true, err) when the protocol was handled and (false, nil)
// when the protocol is unrecognised and the caller should handle the
// connection directly (which for the SNI handler means silently dropping it).
func (h *sniHandler) handleSniffedProtocol(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger, proto string) (handled bool, err error) {
	switch proto {
	case sniffing.ProtoHTTP, sniffing.ProtoTLS:
		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			return h.sniffingDial(ctx, network, address, ro)
		}
		dialTLS := func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
			return h.sniffingDialTLS(ctx, network, address, ro, cfg)
		}
		sniffer := h.sniffer.Build()
		if proto == sniffing.ProtoHTTP {
			return true, sniffer.HandleHTTP(ctx, "tcp", conn,
				sniffing.WithService(h.options.Service),
				sniffing.WithDial(dial),
				sniffing.WithDialTLS(dialTLS),
				sniffing.WithBypass(h.options.Bypass),
				sniffing.WithRecorderObject(ro),
				sniffing.WithLog(log),
			)
		}
		return true, sniffer.HandleTLS(ctx, "tcp", conn,
			sniffing.WithService(h.options.Service),
			sniffing.WithDial(dial),
			sniffing.WithDialTLS(dialTLS),
			sniffing.WithBypass(h.options.Bypass),
			sniffing.WithRecorderObject(ro),
			sniffing.WithLog(log),
		)
	default:
		return false, nil
	}
}
