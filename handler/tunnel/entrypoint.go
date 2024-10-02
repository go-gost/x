package tunnel

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	admission "github.com/go-gost/x/admission/wrapper"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	climiter "github.com/go-gost/x/limiter/conn/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
)

type entrypoint struct {
	node     string
	service  string
	pool     *ConnectorPool
	ingress  ingress.Ingress
	sd       sd.SD
	log      logger.Logger
	recorder recorder.RecorderObject
}

func (ep *entrypoint) handle(ctx context.Context, conn net.Conn) error {
	defer conn.Close()

	start := time.Now()
	log := ep.log.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	br := bufio.NewReader(conn)

	v, err := br.Peek(1)
	if err != nil {
		return err
	}
	if v[0] == relay.Version1 {
		return ep.handleConnect(ctx, xnet.NewReadWriteConn(br, conn, conn), log)
	}

	ro := &xrecorder.HandlerRecorderObject{
		Node:       ep.node,
		Service:    ep.service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Network:    "tcp",
		Time:       start,
	}
	ro.ClientIP, _, _ = net.SplitHostPort(conn.RemoteAddr().String())

	return ep.handleHTTP(ctx, xio.NewReadWriter(br, conn), ro, log)
}

func (ep *entrypoint) handleConnect(ctx context.Context, conn net.Conn, log logger.Logger) error {
	req := relay.Request{}
	if _, err := req.ReadFrom(conn); err != nil {
		return err
	}

	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	var srcAddr, dstAddr string
	network := "tcp"
	var tunnelID relay.TunnelID
	for _, f := range req.Features {
		switch f.Type() {
		case relay.FeatureAddr:
			if feature, _ := f.(*relay.AddrFeature); feature != nil {
				v := net.JoinHostPort(feature.Host, strconv.Itoa(int(feature.Port)))
				if srcAddr != "" {
					dstAddr = v
				} else {
					srcAddr = v
				}
			}
		case relay.FeatureTunnel:
			if feature, _ := f.(*relay.TunnelFeature); feature != nil {
				tunnelID = relay.NewTunnelID(feature.ID[:])
			}
		case relay.FeatureNetwork:
			if feature, _ := f.(*relay.NetworkFeature); feature != nil {
				network = feature.Network.String()
			}
		}
	}

	if tunnelID.IsZero() {
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		return ErrTunnelID
	}

	d := Dialer{
		pool:    ep.pool,
		retry:   3,
		timeout: 15 * time.Second,
		log:     log,
	}
	cc, _, cid, err := d.Dial(ctx, network, tunnelID.String())
	if err != nil {
		log.Error(err)
		resp.Status = relay.StatusServiceUnavailable
		resp.WriteTo(conn)
		return err
	}
	defer cc.Close()

	log.Debugf("new connection to tunnel: %s, connector: %s", tunnelID, cid)

	if _, err := resp.WriteTo(conn); err != nil {
		log.Error(err)
		return err
	}

	af := &relay.AddrFeature{}
	af.ParseFrom(srcAddr)
	resp.Features = append(resp.Features, af) // src address

	af = &relay.AddrFeature{}
	af.ParseFrom(dstAddr)
	resp.Features = append(resp.Features, af) // dst address

	resp.WriteTo(cc)

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())

	return nil
}

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
	// l.logger.Debugf("pp: %d", l.options.ProxyProtocol)
	ln := l.ln
	ln = proxyproto.WrapListener(l.options.ProxyProtocol, ln, 10*time.Second)
	ln = metrics.WrapListener(l.options.Service, ln)
	ln = admission.WrapListener(l.options.Admission, ln)
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
	return h.ep.handle(ctx, conn)
}
