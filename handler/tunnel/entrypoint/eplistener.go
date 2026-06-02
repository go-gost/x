package entrypoint

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/listener"
	md "github.com/go-gost/core/metadata"
	admission "github.com/go-gost/x/admission/wrapper"
	"github.com/go-gost/x/internal/net/proxyproto"
	climiter "github.com/go-gost/x/limiter/conn/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
)

// entrypointHandler wraps an Entrypoint as a handler.Handler for use with
// the service framework (xservice.NewService).
//
// The handler simply delegates Handle() to ep.Handle() — all protocol
// dispatch, ingress resolution, and tunnel dialing are handled inside
// the Entrypoint.
type entrypointHandler struct {
	ep *Entrypoint
}

// NewHandler wraps an Entrypoint as a handler.Handler.
//
// The returned handler's Init is a no-op (the Entrypoint is fully
// initialized by New()). Handle delegates to ep.Handle.
func NewHandler(ep *Entrypoint) handler.Handler {
	return &entrypointHandler{ep: ep}
}

func (h *entrypointHandler) Init(md md.Metadata) (err error) {
	return
}

func (h *entrypointHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	return h.ep.Handle(ctx, conn)
}

// tcpListener wraps a raw net.Listener with GOST listener wrappers in
// the standard order: proxyproto → metrics → admission → conn limiter.
//
// The listener wrappers are applied in Init(), not at construction time,
// to match the GOST service lifecycle pattern.
type tcpListener struct {
	ln      net.Listener
	options listener.Options
}

// NewTCPListener creates a new TCP listener wrapper around a raw net.Listener.
//
// Imports the proxyproto, metrics, admission, and conn-limiter wrappers
// in the standard GOST listener order (see architecture docs). Options
// carry the service name, proxy protocol version, and optional admission/
// conn-limit config.
func NewTCPListener(ln net.Listener, opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &tcpListener{
		ln:      ln,
		options: options,
	}
}

// Init wraps the raw listener with GOST middleware layers:
//  1. proxyproto.WrapListener — PROXY protocol v1/v2 support
//  2. metrics.WrapListener — per-connection metrics
//  3. admission.WrapListener — IP admission control
//  4. climiter.WrapListener — concurrent connection limiting
//
// This ordering matches the GOST convention: metrics/observability
// outermost so dead-on-arrival connections are still counted.
func (l *tcpListener) Init(md md.Metadata) (err error) {
	ln := l.ln
	ln = proxyproto.WrapListener(l.options.ProxyProtocol, ln, 10*time.Second)
	ln = metrics.WrapListener(l.options.Service, ln)
	ln = admission.WrapListener(l.options.Service, l.options.Admission, ln)
	ln = climiter.WrapListener(l.options.ConnLimiter, ln)
	l.ln = ln

	return
}

// Accept accepts the next connection from the wrapped listener.
// Implements listener.Listener.
func (l *tcpListener) Accept() (conn net.Conn, err error) {
	return l.ln.Accept()
}

// Addr returns the listener's network address.
// Implements listener.Listener.
func (l *tcpListener) Addr() net.Addr {
	return l.ln.Addr()
}

// Close closes the wrapped listener.
// Implements listener.Listener.
func (l *tcpListener) Close() error {
	return l.ln.Close()
}