package tunnel

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

const (
	httpHeaderSID           = "Gost-Sid"
	httpHeaderForwardedNode = "Gost-Forwarded-Node"
)

type tcpListener struct {
	ln      net.Listener
	options listener.Options
}

func newTCPListener(ln net.Listener, opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &tcpListener{
		ln:      ln,
		options: options,
	}
}

func (l *tcpListener) Init(md md.Metadata) (err error) {
	ln := l.ln
	ln = proxyproto.WrapListener(l.options.ProxyProtocol, ln, 10*time.Second)
	ln = metrics.WrapListener(l.options.Service, ln)
	ln = admission.WrapListener(l.options.Service, l.options.Admission, ln)
	ln = climiter.WrapListener(l.options.ConnLimiter, ln)
	l.ln = ln

	return
}

func (l *tcpListener) Accept() (conn net.Conn, err error) {
	return l.ln.Accept()
}

func (l *tcpListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *tcpListener) Close() error {
	return l.ln.Close()
}

type entrypointHandler struct {
	ep *entrypoint
}

func (h *entrypointHandler) Init(md md.Metadata) (err error) {
	return
}

func (h *entrypointHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	return h.ep.Handle(ctx, conn)
}