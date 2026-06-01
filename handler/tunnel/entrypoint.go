package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	dissector "github.com/go-gost/tls-dissector"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
)

// entrypoint is a public tunnel entry point that accepts external connections
// and routes them through the tunnel network. It supports three protocols
// determined by the first byte of the connection: relay (Version1), TLS, or HTTP.
type entrypoint struct {
	node      string
	service   string
	pool      *ConnectorPool
	ingress   ingress.Ingress
	sd        sd.SD
	log       logger.Logger
	recorder  recorder.RecorderObject
	transport http.RoundTripper

	sniffingWebsocket   bool
	websocketSampleRate float64

	// readTimeout is applied as SetReadDeadline on the upstream connection
	// before sniffing HTTP/TLS reads. It mirrors entryPointReadTimeout
	// from the handler metadata.
	readTimeout time.Duration
}

func (ep *entrypoint) Handle(ctx context.Context, conn net.Conn) (err error) {
	defer conn.Close()

	ro := &xrecorder.HandlerRecorderObject{
		Network:    "tcp",
		Node:       ep.node,
		Service:    ep.service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		SID:        xctx.SidFromContext(ctx).String(),
		Time:       time.Now(),
	}

	if srcAddr := xctx.SrcAddrFromContext(ctx); srcAddr != nil {
		ro.ClientAddr = srcAddr.String()
	}

	log := ep.log.WithFields(map[string]any{
		"network": ro.Network,
		"remote":  conn.RemoteAddr().String(),
		"local":   conn.LocalAddr().String(),
		"client":  ro.ClientAddr,
		"sid":     ro.SID,
	})
	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(ro.Time)
		if err := ro.Record(ctx, ep.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(ro.Time),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	br := bufio.NewReader(conn)
	v, err := br.Peek(1)
	if err != nil {
		return err
	}

	conn = xnet.NewReadWriteConn(br, conn, conn)
	if v[0] == relay.Version1 {
		return ep.handleConnect(ctx, conn, ro, log)
	}
	if v[0] == dissector.Handshake {
		return ep.handleTLS(ctx, conn, ro, log)
	}
	return ep.handleHTTP(ctx, conn, ro, log)
}

func (ep *entrypoint) dial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	var tunnelID relay.TunnelID
	if ep.ingress != nil {
		if rule := ep.ingress.GetRule(ctx, addr, ingress.WithService(ep.service)); rule != nil {
			tunnelID = parseTunnelID(rule.Endpoint)
		}
	}

	log := ictx.LoggerFromContext(ctx)
	if log == nil {
		log = ep.log
	}
	log.Debugf("dial: new connection to host %s", addr)

	if tunnelID.IsZero() {
		return nil, fmt.Errorf("%w %s", ErrTunnelRoute, addr)
	}

	if ro := ictx.RecorderObjectFromContext(ctx); ro != nil {
		ro.ClientID = tunnelID.String()
	}

	if tunnelID.IsPrivate() {
		return nil, fmt.Errorf("%w: tunnel %s is private for host %s", ErrPrivateTunnel, tunnelID, addr)
	}

	log = log.WithFields(map[string]any{
		"tunnel": tunnelID.String(),
	})

	d := &Dialer{
		node:    ep.node,
		pool:    ep.pool,
		sd:      ep.sd,
		retry:   3,
		timeout: 15 * time.Second,
		log:     log,
	}
	conn, node, cid, err := d.Dial(ctx, "tcp", tunnelID.String())
	if err != nil {
		return
	}
	log.Debugf("dial: connected to host %s, tunnel: %s, connector: %s", addr, tunnelID, cid)

	ro := ictx.RecorderObjectFromContext(ctx)
	if node == ep.node {
		if ro != nil {
			ro.Redirect = ""
		}

		var clientAddr string
		if addr := xctx.SrcAddrFromContext(ctx); addr != nil {
			clientAddr = addr.String()
		}
		var features []relay.Feature
		af := &relay.AddrFeature{}
		af.ParseFrom(string(clientAddr))
		features = append(features, af) // src address

		af = &relay.AddrFeature{}
		af.ParseFrom(addr)
		features = append(features, af) // dst address

		if _, err = (&relay.Response{
			Version:  relay.Version1,
			Status:   relay.StatusOK,
			Features: features,
		}).WriteTo(conn); err != nil {
			conn.Close()
			return nil, err
		}
	} else {
		if ro != nil {
			ro.Redirect = node
		}
	}

	return conn, nil
}