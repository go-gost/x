package v5

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/resolver"
	"github.com/go-gost/gosocks5"
	ctxvalue "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/udp"
	"github.com/go-gost/x/internal/util/socks"
	traffic_wrapper "github.com/go-gost/x/limiter/traffic/wrapper"
	metrics "github.com/go-gost/x/metrics/wrapper"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
)

func (h *socks5Handler) handleUDP(ctx context.Context, conn net.Conn, network string, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	log = log.WithFields(map[string]any{
		"network": network,
		"cmd":     network,
	})

	if !h.md.enableUDP {
		reply := gosocks5.NewReply(gosocks5.NotAllowed, nil)
		log.Trace(reply)
		log.Error("socks5: UDP relay is disabled")
		return reply.Write(conn)
	}

	// Bind the client-facing relay socket to the TCP control connection's local
	// IP — the address advertised to the client as BND.ADDR — so replies sent
	// from this socket carry the matching source IP. A wildcard bind lets the
	// kernel pick the interface's primary IP, which mismatches BND.ADDR and
	// makes compliant clients drop the replies (RFC 1928 §6). This is what
	// breaks UDP associate under multiple IP aliases (metadata.interface).
	host, _, _ := net.SplitHostPort(conn.LocalAddr().String())

	lc := xnet.ListenConfig{
		Netns: h.options.Netns,
	}

	cc, err := listenPacketInRange(ctx, &lc, network, host, h.md.udpBindMin, h.md.udpBindMax)
	if err != nil {
		log.Error(err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		log.Trace(reply)
		reply.Write(conn)
		return err
	}
	defer cc.Close()

	log = log.WithFields(map[string]any{
		"src":  cc.LocalAddr().String(),
		"bind": cc.LocalAddr().String(),
	})
	ro.SrcAddr = cc.LocalAddr().String()

	// Verify the upstream chain is reachable before replying Success,
	// per RFC 1928 §7.
	var buf bytes.Buffer
	c, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), network, "") // UDP association
	ro.Route = buf.String()
	if err != nil {
		log.Error(err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		log.Trace(reply)
		reply.Write(conn)
		return err
	}
	defer c.Close()

	pc, ok := c.(net.PacketConn)
	if !ok {
		err := errors.New("socks5: wrong connection type")
		log.Error(err)
		reply := gosocks5.NewReply(gosocks5.Failure, nil)
		log.Trace(reply)
		reply.Write(conn)
		return err
	}

	// A direct (no-chain) UDP association yields a raw *net.UDPConn, which
	// cannot consume the domainAddr returned by udpConn.ReadFrom for
	// ATYP=DOMAINNAME datagrams. Wrap it so domains are resolved through the
	// configured resolver (hostMapper → resolver → system DNS) instead of the
	// previous hardcoded net.ResolveUDPAddr in the SOCKS5 decode path.
	// Chain-backed PacketConns (udpTunConn, udpRelayConn, ...) encode domains
	// as ATYP=Domain themselves and are left untouched.
	if _, isDirect := pc.(*net.UDPConn); isDirect {
		pc = &resolvePacketConn{
			PacketConn:  pc,
			resolver:    h.options.Router.Options().Resolver,
			hostMapper:  h.options.Router.Options().HostMapper,
		}
	}

	saddr := gosocks5.Addr{}
	saddr.ParseFrom(cc.LocalAddr().String())

	saddr.Host = host
	if v := net.ParseIP(h.md.publicAddr); v != nil {
		saddr.Host = h.md.publicAddr
	}
	saddr.Type = 0
	reply := gosocks5.NewReply(gosocks5.Succeeded, &saddr)
	log.Trace(reply)
	if err := reply.Write(conn); err != nil {
		log.Error(err)
		return err
	}

	log.Debugf("bind on %s OK", cc.LocalAddr())
	pc = metrics.WrapPacketConn(ro.Service, pc)

	{
		pStats := xstats.Stats{}
		cc = stats_wrapper.WrapPacketConn(cc, &pStats)

		defer func() {
			ro.InputBytes += pStats.Get(stats.KindInputBytes)
			ro.OutputBytes += pStats.Get(stats.KindOutputBytes)
		}()

		clientID := ctxvalue.ClientIDFromContext(ctx)
		cc = traffic_wrapper.WrapPacketConn(
			cc,
			h.limiter,
			string(clientID),
			limiter.ServiceOption(h.options.Service),
			limiter.ScopeOption(limiter.ScopeClient),
			limiter.NetworkOption(network),
			limiter.ClientOption(string(clientID)),
			limiter.SrcOption(conn.RemoteAddr().String()),
		)
		if h.options.Observer != nil {
			pstats := h.stats.Stats(string(clientID))
			pstats.Add(stats.KindTotalConns, 1)
			pstats.Add(stats.KindCurrentConns, 1)
			defer pstats.Add(stats.KindCurrentConns, -1)
			cc = stats_wrapper.WrapPacketConn(cc, pstats)
		}
	}

	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		err := fmt.Errorf("socks5 udp: unexpected remote address type %T", conn.RemoteAddr())
		log.Error(err)
		return err
	}
	pc1 := socks.UDPConn(
		&filteredPacketConn{
			PacketConn: cc,
			filterIP:   tcpAddr.IP,
		},
		h.md.udpBufferSize)

	if h.md.udpResolveDomain {
		pc1 = &domainResolvePacketConn{
			PacketConn: pc1,
			resolver:   h.options.Router.Options().Resolver,
			hostMapper: h.options.Router.Options().HostMapper,
			log:        log,
		}
	}

	r := udp.NewRelay(pc1, pc).
		WithService(h.options.Service).
		WithBypass(h.options.Bypass).
		WithBufferSize(h.md.udpBufferSize).
		WithLogger(log)

	go r.Run(ctx)

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), cc.LocalAddr())
	io.Copy(io.Discard, conn)
	log.WithFields(map[string]any{"duration": time.Since(t)}).
		Debugf("%s >-< %s", conn.RemoteAddr(), cc.LocalAddr())

	return nil
}

// listenPacketInRange binds the client-facing UDP relay socket. When lo..hi is
// a valid range (lo > 0, hi >= lo) it scans ports from a random offset within
// [lo, hi] and retries on EADDRINUSE, so a NAT router can forward a small,
// fixed port set to the SOCKS server. The random offset avoids every
// association hammering port lo under concurrency; the rotation visits distinct
// ports, so a free port is always found when the range fits the attempt cap.
// RFC 1928 leaves relay-port selection to the server; the caller still reports
// the actually-bound port via BND.PORT. With no range, the OS chooses (port 0).
// A non-EADDRINUSE error fails fast.
func listenPacketInRange(ctx context.Context, lc *xnet.ListenConfig, network, host string, lo, hi int) (net.PacketConn, error) {
	if lo > 0 && hi >= lo {
		span := hi - lo + 1
		attempts := min(span, 64)
		offset := rand.IntN(span)
		var lastErr error
		for i := range attempts {
			port := lo + (offset+i)%span
			cc, err := lc.ListenPacket(ctx, network, net.JoinHostPort(host, strconv.Itoa(port)))
			if err == nil {
				return cc, nil
			}
			lastErr = err
			if !errors.Is(err, syscall.EADDRINUSE) {
				return nil, err
			}
		}
		return nil, lastErr
	}
	return lc.ListenPacket(ctx, network, net.JoinHostPort(host, "0"))
}

// filteredPacketConn implements SOCKS5 RFC 1928 UDP relay security by filtering
// incoming packets to only accept those from the client IP that established the TCP control connection.
type filteredPacketConn struct {
	net.PacketConn
	filterIP net.IP // The expected client IP from the SOCKS5 TCP connection
}

func (f *filteredPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = f.PacketConn.ReadFrom(p)
		if err != nil {
			return
		}

		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		if udpAddr.IP.Equal(f.filterIP) {
			return
		}
	}
}

// resolvePacketConn wraps the upstream net.PacketConn for a direct (no-chain)
// UDP association and resolves domain addresses to IPs in WriteTo calls.
//
// udpConn.ReadFrom now returns a domainAddr for ATYP=DOMAINNAME datagrams so
// the domain survives to the chain; a raw *net.UDPConn cannot consume a
// domainAddr (WriteTo needs *net.UDPAddr), so direct connections are wrapped
// here. Resolution order is hostMapper → configured resolver → system DNS, so a
// configured resolver (e.g. resolver=1.1.1.1) is honored instead of leaking
// through the system resolver.
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
		return 0, fmt.Errorf("socks5 udp: cannot resolve %s", host)
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

// domainResolvePacketConn wraps a net.PacketConn and resolves domain
// addresses to IPs in WriteTo calls. This guarantees that SOCKS5 UDP
// response datagrams never carry ATYP=Domain (0x03), which some clients
// (e.g., tun2proxy, Surge) cannot parse.
type domainResolvePacketConn struct {
	net.PacketConn
	resolver   resolver.Resolver
	hostMapper hosts.HostMapper
	log        logger.Logger
}

func (c *domainResolvePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return c.PacketConn.WriteTo(b, addr)
	}
	if net.ParseIP(host) != nil {
		// Already an IP address — pass through unchanged.
		return c.PacketConn.WriteTo(b, addr)
	}

	// Resolve the domain using the router's infrastructure
	// (host mapper → resolver → system fallback) so the SOCKS5 encoder
	// will use AddrIPv4 or AddrIPv6 instead of AddrDomain.
	var ips []net.IP
	if c.hostMapper != nil {
		ips, _ = c.hostMapper.Lookup(context.Background(), "ip", host)
	}
	if len(ips) == 0 && c.resolver != nil {
		ips, err = c.resolver.Resolve(context.Background(), "ip", host)
		if err != nil && c.log != nil {
			c.log.Warnf("socks5 udp: resolve %s: %v", host, err)
		}
	}
	if len(ips) == 0 {
		ips, err = net.LookupIP(host)
	}
	if err != nil || len(ips) == 0 {
		// Cannot resolve the domain — drop the datagram rather than
		// forwarding an ATYP=Domain response the client cannot parse.
		if c.log != nil {
			c.log.Warnf("socks5 udp: dropping datagram to %s (DNS resolution failed)", host)
		}
		if err == nil {
			err = fmt.Errorf("socks5 udp: DNS resolution failed for %s", host)
		}
		return 0, err
	}

	// Pick the first IPv4 address from the result set, falling back to
	// the first entry when no IPv4 is available.
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
