package relay

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/listener"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/relay"
	admission "github.com/go-gost/x/admission/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/internal/util/forward"
	climiter "github.com/go-gost/x/limiter/conn/wrapper"
	limiter "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
)

type epListener struct {
	ln      net.Listener
	options listener.Options
}

func NewEntryPointListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &epListener{
		options: options,
	}
}

func (l *epListener) Init(md md.Metadata) (err error) {
	network := "tcp"
	if xnet.IsIPv4(l.options.Addr) {
		network = "tcp4"
	}
	ln, err := net.Listen(network, l.options.Addr)
	if err != nil {
		return
	}

	// l.logger.Debugf("pp: %d", l.options.ProxyProtocol)

	ln = metrics.WrapListener(l.options.Service, ln)
	ln = proxyproto.WrapListener(l.options.ProxyProtocol, ln, 10*time.Second)
	ln = admission.WrapListener(l.options.Admission, ln)
	ln = limiter.WrapListener(l.options.TrafficLimiter, ln)
	ln = climiter.WrapListener(l.options.ConnLimiter, ln)
	l.ln = ln

	return
}

func (l *epListener) Accept() (conn net.Conn, err error) {
	return l.ln.Accept()
}

func (l *epListener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *epListener) Close() error {
	return l.ln.Close()
}

type epHandler struct {
	pool    *ConnectorPool
	ingress ingress.Ingress
	options handler.Options
}

func NewEntryPointHandler(pool *ConnectorPool, ingress ingress.Ingress, opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &epHandler{
		pool:    pool,
		ingress: ingress,
		options: options,
	}
}

func (h *epHandler) Init(md md.Metadata) (err error) {
	return
}

func (h *epHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	start := time.Now()
	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	var rw io.ReadWriter = conn
	var host string
	var protocol string
	rw, host, protocol, _ = forward.Sniffing(ctx, conn)
	h.options.Logger.Debugf("sniffing: host=%s, protocol=%s", host, protocol)

	var tunnelID relay.TunnelID
	if h.ingress != nil {
		tunnelID = parseTunnelID(h.ingress.Get(host))
	}
	if tunnelID.IsPrivate() {
		err := fmt.Errorf("access denied: tunnel %s is private", tunnelID)
		log.Error(err)
		return err
	}
	log = log.WithFields(map[string]any{
		"tunnel": tunnelID.String(),
	})

	cc, err := getTunnelConn("tcp", h.pool, tunnelID, 3, log)
	if err != nil {
		log.Error(err)
		return err
	}
	defer cc.Close()

	log.Debugf("%s >> %s", conn.RemoteAddr(), cc.RemoteAddr())

	af := &relay.AddrFeature{}
	af.ParseFrom(conn.RemoteAddr().String())
	resp := relay.Response{
		Version:  relay.Version1,
		Status:   relay.StatusOK,
		Features: []relay.Feature{af},
	}
	resp.WriteTo(cc)

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	xnet.Transport(rw, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())

	return nil
}
