package relay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/relay"
	admission "github.com/go-gost/x/admission/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/internal/util/forward"
	"github.com/go-gost/x/internal/util/mux"
	climiter "github.com/go-gost/x/limiter/conn/wrapper"
	limiter "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
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
	// l.logger.Debugf("pp: %d", l.options.ProxyProtocol)
	ln := l.ln
	ln = proxyproto.WrapListener(l.options.ProxyProtocol, ln, 10*time.Second)
	ln = metrics.WrapListener(l.options.Service, ln)
	ln = admission.WrapListener(l.options.Admission, ln)
	ln = limiter.WrapListener(l.options.TrafficLimiter, ln)
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

type tcpHandler struct {
	session *mux.Session
	options handler.Options
}

func newTCPHandler(session *mux.Session, opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &tcpHandler{
		session: session,
		options: options,
	}
}

func (h *tcpHandler) Init(md md.Metadata) (err error) {
	return
}

func (h *tcpHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
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

	cc, err := h.session.GetConn()
	if err != nil {
		log.Error(err)
		return err
	}
	defer cc.Close()

	af := &relay.AddrFeature{}
	af.ParseFrom(conn.RemoteAddr().String())
	resp := relay.Response{
		Version:  relay.Version1,
		Status:   relay.StatusOK,
		Features: []relay.Feature{af},
	}
	if _, err := resp.WriteTo(cc); err != nil {
		log.Error(err)
		return err
	}

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	xnet.Transport(conn, cc)
	log.WithFields(map[string]any{"duration": time.Since(t)}).
		Debugf("%s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())
	return nil
}

type tunnelHandler struct {
	pool    *ConnectorPool
	ingress ingress.Ingress
	options handler.Options
}

func newTunnelHandler(pool *ConnectorPool, ingress ingress.Ingress, opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &tunnelHandler{
		pool:    pool,
		ingress: ingress,
		options: options,
	}
}

func (h *tunnelHandler) Init(md md.Metadata) (err error) {
	return
}

func (h *tunnelHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
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

	if protocol == forward.ProtoHTTP {
		return h.handleHTTP(ctx, conn.RemoteAddr(), rw, log)
	}

	var tunnelID relay.TunnelID
	if h.ingress != nil {
		tunnelID = parseTunnelID(h.ingress.Get(ctx, host))
	}
	if tunnelID.IsZero() {
		err := fmt.Errorf("no route to host %s", host)
		log.Error(err)
		return err
	}
	if tunnelID.IsPrivate() {
		err := fmt.Errorf("access denied: tunnel %s is private for host %s", tunnelID, host)
		log.Error(err)
		return err
	}
	log = log.WithFields(map[string]any{
		"tunnel": tunnelID.String(),
	})

	cc, _, err := getTunnelConn("tcp", h.pool, tunnelID, 3, log)
	if err != nil {
		log.Error(err)
		return err
	}
	defer cc.Close()

	log.Debugf("%s >> %s", conn.RemoteAddr(), cc.RemoteAddr())

	var features []relay.Feature
	af := &relay.AddrFeature{}
	af.ParseFrom(conn.RemoteAddr().String()) // client address
	features = append(features, af)

	if host != "" {
		// target host
		af := &relay.AddrFeature{}
		af.ParseFrom(host)
		features = append(features, af)
	}

	resp := relay.Response{
		Version:  relay.Version1,
		Status:   relay.StatusOK,
		Features: features,
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

func (h *tunnelHandler) handleHTTP(ctx context.Context, raddr net.Addr, rw io.ReadWriter, log logger.Logger) (err error) {
	br := bufio.NewReader(rw)

	for {
		resp := &http.Response{
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
			StatusCode: http.StatusServiceUnavailable,
		}

		err = func() error {
			req, err := http.ReadRequest(br)
			if err != nil {
				return err
			}

			var tunnelID relay.TunnelID
			if h.ingress != nil {
				tunnelID = parseTunnelID(h.ingress.Get(ctx, req.Host))
			}
			if tunnelID.IsZero() {
				err := fmt.Errorf("no route to host %s", req.Host)
				log.Error(err)
				resp.StatusCode = http.StatusBadGateway
				return resp.Write(rw)
			}
			if tunnelID.IsPrivate() {
				err := fmt.Errorf("access denied: tunnel %s is private for host %s", tunnelID, req.Host)
				log.Error(err)
				resp.StatusCode = http.StatusBadGateway
				return resp.Write(rw)
			}

			log = log.WithFields(map[string]any{
				"host":   req.Host,
				"tunnel": tunnelID.String(),
			})

			cc, cid, err := getTunnelConn("tcp", h.pool, tunnelID, 3, log)
			if err != nil {
				log.Error(err)
				return resp.Write(rw)
			}
			defer cc.Close()

			log.Debugf("new connection to tunnel %s(connector %s)", tunnelID, cid)

			var features []relay.Feature
			af := &relay.AddrFeature{}
			af.ParseFrom(raddr.String())
			features = append(features, af)

			if host := req.Host; host != "" {
				if h, _, _ := net.SplitHostPort(host); h == "" {
					host = net.JoinHostPort(host, "80")
				}
				af := &relay.AddrFeature{}
				af.ParseFrom(host)
				features = append(features, af)
			}

			(&relay.Response{
				Version:  relay.Version1,
				Status:   relay.StatusOK,
				Features: features,
			}).WriteTo(cc)

			if log.IsLevelEnabled(logger.TraceLevel) {
				dump, _ := httputil.DumpRequest(req, false)
				log.Trace(string(dump))
			}
			if err := req.Write(cc); err != nil {
				log.Warnf("send request to tunnel %s: %v", tunnelID, err)
				return resp.Write(rw)
			}

			res, err := http.ReadResponse(bufio.NewReader(cc), req)
			if err != nil {
				log.Warnf("read response from tunnel %s: %v", tunnelID, err)
				return resp.Write(rw)
			}
			defer res.Body.Close()

			return res.Write(rw)
		}()
		if err != nil {
			// log.Error(err)
			break
		}
	}

	return
}
