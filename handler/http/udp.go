package http

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"

	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/logger"
	stats "github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/resolver"
	ictx "github.com/go-gost/x/internal/ctx"
	"github.com/go-gost/x/internal/net/udp"
	"github.com/go-gost/x/internal/util/socks"
	xrecorder "github.com/go-gost/x/recorder"
)

// handleUDP implements UDP over HTTP (UDP relay). When the client sets the
// X-Gost-Protocol header to "udp", the handler responds with 200 OK and
// establishes a UDP association through the proxy chain. Client data sent
// over the HTTP connection is wrapped as SOCKS5 UDP packets and relayed
// through the UDP tunnel.
//
// If UDP relay is disabled (enableUDP=false), a 403 Forbidden is returned.
func (h *httpHandler) handleUDP(ctx context.Context, conn net.Conn, clientID string, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"cmd": "udp",
	})

	resp := &http.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     h.md.header,
	}
	if resp.Header == nil {
		resp.Header = http.Header{}
	}

	if !h.md.enableUDP {
		resp.StatusCode = http.StatusForbidden

		if log.IsLevelEnabled(logger.TraceLevel) {
			dump, _ := httputil.DumpResponse(resp, false)
			log.Trace(string(dump))
		}

		log.Error("http: UDP relay is disabled")

		return resp.Write(conn)
	}

	resp.StatusCode = http.StatusOK
	if log.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Trace(string(dump))
	}
	if err := resp.Write(conn); err != nil {
		log.Error(err)
		return err
	}

	if h.options.Observer != nil {
		pstats := h.stats.Stats(clientID)
		pstats.Add(stats.KindTotalConns, 1)
		pstats.Add(stats.KindCurrentConns, 1)
		defer pstats.Add(stats.KindCurrentConns, -1)
	}

	// Dial a UDP association through the proxy chain router. The empty
	// address signals that the router should create a UDP socket rather
	// than connect to a specific target.
	if h.options.Router == nil {
		return errors.New("nil router")
	}
	var buf bytes.Buffer
	c, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), "udp", "")
	ro.Route = buf.String()
	if err != nil {
		log.Error(err)
		return err
	}
	defer c.Close()

	log.WithFields(map[string]any{"src": c.LocalAddr().String()})
	ro.SrcAddr = c.LocalAddr().String()

	pc, ok := c.(net.PacketConn)
	if !ok {
		err = errors.New("wrong connection type")
		log.Error(err)
		return err
	}

	// Wrap raw *net.UDPConn so domainAddr from socks.UDPTunServerConn.ReadFrom
	// are resolved through the configured resolver instead of failing WriteTo.
	if _, ok := pc.(*net.UDPConn); ok {
		pc = &resolvePacketConn{
			PacketConn: pc,
			resolver:   h.options.Router.Options().Resolver,
			hostMapper: h.options.Router.Options().HostMapper,
		}
	}

	// Wrap the HTTP connection as a SOCKS5 UDP tunnel server conn so
	// that the relay can read/write SOCKS5-encapsulated UDP datagrams.
	relay := udp.NewRelay(socks.UDPTunServerConn(conn), pc).
		WithService(h.options.Service).
		WithBypass(h.options.Bypass).
		WithBufferSize(h.md.udpBufferSize).
		WithLogger(log)

	t := time.Now()
	log.Infof("%s <-> %s", conn.RemoteAddr(), pc.LocalAddr())
	relay.Run(ctx)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), pc.LocalAddr())

	return nil
}

// resolvePacketConn wraps a net.PacketConn and resolves domain addresses
// in WriteTo calls through hostMapper → configured resolver → system DNS.
type resolvePacketConn struct {
	net.PacketConn
	resolver   resolver.Resolver
	hostMapper hosts.HostMapper
}

func (c *resolvePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return c.PacketConn.WriteTo(b, addr)
	}
	if net.ParseIP(host) != nil {
		return c.PacketConn.WriteTo(b, addr)
	}

	var ips []net.IP
	if c.hostMapper != nil {
		ips, _ = c.hostMapper.Lookup(context.Background(), "ip", host)
	}
	if len(ips) == 0 && c.resolver != nil {
		ips, _ = c.resolver.Resolve(context.Background(), "ip", host)
	}
	if len(ips) == 0 {
		ips, _ = net.LookupIP(host)
	}
	if len(ips) == 0 {
		return 0, fmt.Errorf("http udp: cannot resolve %s", host)
	}

	ip := ips[0]
	for _, candidate := range ips {
		if candidate.To4() != nil {
			ip = candidate
			break
		}
	}
	port, _ := strconv.Atoi(portStr)
	return c.PacketConn.WriteTo(b, &net.UDPAddr{IP: ip, Port: port})
}
