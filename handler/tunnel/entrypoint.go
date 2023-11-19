package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	admission "github.com/go-gost/x/admission/wrapper"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	climiter "github.com/go-gost/x/limiter/conn/wrapper"
	limiter "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
)

type entrypoint struct {
	node    string
	pool    *ConnectorPool
	ingress ingress.Ingress
	sd      sd.SD
	log     logger.Logger
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
		return ep.handleConnect(ctx, xnet.NewBufferReaderConn(conn, br), log)
	}

	var cc net.Conn
	for {
		resp := &http.Response{
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
			StatusCode: http.StatusServiceUnavailable,
		}

		err := func() error {
			req, err := http.ReadRequest(br)
			if err != nil {
				// log.Errorf("read http request: %v", err)
				return err
			}

			if log.IsLevelEnabled(logger.TraceLevel) {
				dump, _ := httputil.DumpRequest(req, false)
				log.Trace(string(dump))
			}

			var tunnelID relay.TunnelID
			if ep.ingress != nil {
				if rule := ep.ingress.GetRule(ctx, req.Host); rule != nil {
					tunnelID = parseTunnelID(rule.Endpoint)
				}
			}
			if tunnelID.IsZero() {
				err := fmt.Errorf("no route to host %s", req.Host)
				log.Error(err)
				resp.StatusCode = http.StatusBadGateway
				return resp.Write(conn)
			}
			if tunnelID.IsPrivate() {
				err := fmt.Errorf("access denied: tunnel %s is private for host %s", tunnelID, req.Host)
				log.Error(err)
				resp.StatusCode = http.StatusBadGateway
				return resp.Write(conn)
			}

			log = log.WithFields(map[string]any{
				"host":   req.Host,
				"tunnel": tunnelID.String(),
			})

			remoteAddr := conn.RemoteAddr()
			if addr := ep.getRealClientAddr(req, remoteAddr); addr != remoteAddr {
				log = log.WithFields(map[string]any{
					"src": addr.String(),
				})
				remoteAddr = addr
			}

			d := &Dialer{
				node:    ep.node,
				pool:    ep.pool,
				sd:      ep.sd,
				retry:   3,
				timeout: 15 * time.Second,
				log:     log,
			}
			cc, node, cid, err := d.Dial(ctx, "tcp", tunnelID.String())
			if err != nil {
				log.Error(err)
				return resp.Write(conn)
			}
			log.Debugf("new connection to tunnel: %s, connector: %s", tunnelID, cid)

			host := req.Host
			if h, _, _ := net.SplitHostPort(host); h == "" {
				host = net.JoinHostPort(host, "80")
			}

			if node == ep.node {
				var features []relay.Feature
				af := &relay.AddrFeature{}
				af.ParseFrom(remoteAddr.String())
				features = append(features, af) // src address

				af = &relay.AddrFeature{}
				af.ParseFrom(host)
				features = append(features, af) // dst address

				(&relay.Response{
					Version:  relay.Version1,
					Status:   relay.StatusOK,
					Features: features,
				}).WriteTo(cc)
			}

			if err := req.Write(cc); err != nil {
				cc.Close()
				log.Errorf("send request: %v", err)
				return resp.Write(conn)
			}

			if req.Header.Get("Upgrade") == "websocket" {
				err := xnet.Transport(cc, xio.NewReadWriter(br, conn))
				if err == nil {
					err = io.EOF
				}
				return err
			}

			go func() {
				defer cc.Close()

				t := time.Now()
				log.Debugf("%s <-> %s", remoteAddr, host)

				defer func() {
					log.WithFields(map[string]any{
						"duration": time.Since(t),
					}).Debugf("%s >-< %s", remoteAddr, host)
				}()

				res, err := http.ReadResponse(bufio.NewReader(cc), req)
				if err != nil {
					log.Errorf("read response: %v", err)
					resp.Write(conn)
					return
				}

				if log.IsLevelEnabled(logger.TraceLevel) {
					dump, _ := httputil.DumpResponse(res, false)
					log.Trace(string(dump))
				}

				if err = res.Write(conn); err != nil {
					log.Errorf("write response: %v", err)
				}
			}()

			return nil
		}()

		if err != nil {
			if cc != nil {
				cc.Close()
			}
			break
		}
	}

	return nil
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

func (ep *entrypoint) getRealClientAddr(req *http.Request, raddr net.Addr) net.Addr {
	if req == nil {
		return nil
	}
	// cloudflare CDN
	sip := req.Header.Get("CF-Connecting-IP")
	if sip == "" {
		ss := strings.Split(req.Header.Get("X-Forwarded-For"), ",")
		if len(ss) > 0 && ss[0] != "" {
			sip = ss[0]
		}
	}
	if sip == "" {
		sip = req.Header.Get("X-Real-Ip")
	}

	ip := net.ParseIP(sip)
	if ip == nil {
		return raddr
	}

	_, sp, _ := net.SplitHostPort(raddr.String())

	port, _ := strconv.Atoi(sp)

	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
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

type entrypointHandler struct {
	ep *entrypoint
}

func (h *entrypointHandler) Init(md md.Metadata) (err error) {
	return
}

func (h *entrypointHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	return h.ep.handle(ctx, conn)
}
