package tungo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/AeroCore-IO/avionics/pkg/decision"
	"github.com/go-gost/core/bypass"
	corechain "github.com/go-gost/core/chain"
	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	xchain "github.com/go-gost/x/chain"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/sniffing"
	stats_util "github.com/go-gost/x/internal/util/stats"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/miekg/dns"
	"github.com/rs/xid"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
)

const (
	// udpSessionTimeout is the default timeout for UDP sessions.
	udpSessionTimeout = 30 * time.Second
)

var _ adapter.TransportHandler = (*transportHandler)(nil)

type transportHandler struct {
	service string
	dec     interface {
		CheckTrafficRules(input decision.RuleInput) *decision.TrafficDecision
		ResolveMetadata(srcIP, dstIP string, srcPort, dstPort int, proto string) (appID string, hostname string)
	}
	forwarder hop.Hop
	conntrack *conntrackTable

	conntrackCleanupInterval time.Duration
	udpConntrackTTL          time.Duration
	tcpConntrackTTLShort     time.Duration
	tcpConntrackTTLLong      time.Duration

	// Unbuffered TCP/UDP queues.
	tcpQueue chan adapter.TCPConn
	udpQueue chan adapter.UDPConn

	procOnce   sync.Once
	procCancel context.CancelFunc

	// UDP session timeout.
	udpTimeout    time.Duration
	udpBufferSize int

	sniffing                bool
	sniffingUDP             bool
	sniffingTimeout         time.Duration
	sniffingResponseTimeout time.Duration
	sniffingFallback        bool

	stats    *stats_util.HandlerStats
	recorder recorder.RecorderObject

	ipv6 bool

	opts *handler.Options
}

func (h *transportHandler) HandleTCP(conn adapter.TCPConn) {
	h.tcpQueue <- conn
}

func (h *transportHandler) HandleUDP(conn adapter.UDPConn) {
	h.udpQueue <- conn
}

func (h *transportHandler) process(ctx context.Context) {
	var cleanupTicker *time.Ticker
	if h.conntrack != nil {
		interval := h.conntrackCleanupInterval
		if interval <= 0 {
			interval = 30 * time.Second
		}
		cleanupTicker = time.NewTicker(interval)
		defer cleanupTicker.Stop()
	}

	for {
		select {
		case conn := <-h.tcpQueue:
			go h.handleTCPConn(conn)
		case conn := <-h.udpQueue:
			go h.handleUDPConn(conn)
		case <-func() <-chan time.Time {
			if cleanupTicker == nil {
				return nil
			}
			return cleanupTicker.C
		}():
			_ = h.conntrack.Cleanup(time.Now())
		case <-ctx.Done():
			return
		}
	}
}

type touchConn struct {
	net.Conn
	touch func()
}

func (c *touchConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.touch != nil {
		c.touch()
	}
	return n, err
}

func (c *touchConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 && c.touch != nil {
		c.touch()
	}
	return n, err
}

func (h *transportHandler) flowKeyTCP(srcIP, dstIP netip.Addr, srcPort, dstPort uint16) flowKey {
	return flowKey{proto: flowProtoTCP, srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort}
}

func (h *transportHandler) flowKeyUDP(srcIP, dstIP netip.Addr, srcPort, dstPort uint16) flowKey {
	return flowKey{proto: flowProtoUDP, srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort}
}

func (h *transportHandler) getCachedPolicy(now time.Time, k flowKey) (flowPolicy, bool) {
	if h == nil || h.conntrack == nil {
		return flowPolicy{}, false
	}
	return h.conntrack.Get(now, k)
}

func (h *transportHandler) putCachedPolicy(now time.Time, k flowKey, p flowPolicy, ttl time.Duration) {
	if h == nil || h.conntrack == nil {
		return
	}
	h.conntrack.Put(now, k, p, ttl)
}

func (h *transportHandler) touchPolicy(now time.Time, k flowKey, ttl time.Duration) {
	if h == nil || h.conntrack == nil {
		return
	}
	h.conntrack.Touch(now, k, ttl)
}

// ProcessAsync can be safely called multiple times, but will only be effective once.
func (h *transportHandler) ProcessAsync() {
	h.procOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		h.procCancel = cancel
		go h.process(ctx)
	})
}

// Close closes the Tunnel and releases its resources.
func (h *transportHandler) Close() {
	h.procCancel()
}

func (h *transportHandler) handleTCPConn(originConn adapter.TCPConn) {
	defer originConn.Close()

	id := originConn.ID()

	remoteIP, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	dstIP, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())

	remoteAddr := netip.AddrPortFrom(remoteIP, id.RemotePort)
	dstAddr := netip.AddrPortFrom(dstIP, id.LocalPort)

	start := time.Now()

	sid := xid.New().String()
	ctx := xctx.ContextWithSid(context.Background(), xctx.Sid(sid))

	network := "tcp"
	if remoteIP.Unmap().Is6() && h.ipv6 {
		network = "tcp6"
	}

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.opts.Service,
		Network:    network,
		RemoteAddr: remoteAddr.String(),
		DstAddr:    dstAddr.String(),
		Host:       dstAddr.String(),
		ClientAddr: remoteAddr.String(),
		Time:       start,
		SID:        sid,
	}

	log := h.opts.Logger.WithFields(map[string]any{
		"network": ro.Network,
		"remote":  ro.RemoteAddr,
		"dst":     ro.DstAddr,
		"client":  ro.ClientAddr,
		"sid":     ro.SID,
	})

	log.Debugf("%s <> %s", remoteAddr.String(), dstAddr.String())

	key := h.flowKeyTCP(remoteIP, dstIP, id.RemotePort, id.LocalPort)

	var err error
	var conn net.Conn = originConn

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(start)
		if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"src":         ro.SrcAddr,
			"duration":    time.Since(start),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >< %s", remoteAddr.String(), dstAddr.String())
	}()

	if pstats := h.stats.Stats(""); pstats != nil {
		pstats.Add(stats.KindTotalConns, 1)
		pstats.Add(stats.KindCurrentConns, 1)
		defer pstats.Add(stats.KindCurrentConns, -1)
		rw := stats_wrapper.WrapReadWriter(conn, pstats)
		conn = xnet.NewReadWriteConn(rw, rw, conn)
	}

	if h.sniffing {
		if h.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(h.sniffingTimeout))
		}

		br := bufio.NewReader(conn)
		proto, _ := sniffing.Sniff(ctx, br)
		ro.Proto = proto

		if h.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Time{})
		}

		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			var cc net.Conn
			var err error
			now := time.Now()
			p, ok := h.getCachedPolicy(now, key)
			if !ok {
				useProxy := false
				if h.dec != nil {
					appID, hostname := h.dec.ResolveMetadata(remoteIP.String(), dstIP.String(), int(id.RemotePort), int(id.LocalPort), "TCP")
					if hostname == "" {
						if host, _, _ := net.SplitHostPort(address); host != "" {
							hostname = host
						} else if strings.TrimSpace(address) != "" {
							hostname = strings.TrimSpace(address)
						}
					}
					if hostname == "" {
						type domainLookup interface{ GetDomainsForIP(string) []string }
						if dl, ok := any(h.dec).(domainLookup); ok {
							if domains := dl.GetDomainsForIP(dstIP.String()); len(domains) > 0 {
								hostname = domains[0]
							}
						}
					}
					if d := h.dec.CheckTrafficRules(decision.RuleInput{
						SteamAppID: appID,
						DestHost:   dstIP.String(),
						DestPort:   int32(id.LocalPort),
						Protocol:   "TCP",
						DestDomain: hostname,
					}); d != nil {
						log.Debugf("traffic decision: action=%s rule=%s appID=%s dst=%s domain=%s", d.Action, d.RuleName, appID, dstAddr.String(), hostname)
						if strings.EqualFold(strings.TrimSpace(string(d.Action)), "PROXY") {
							useProxy = true
						}
					}
				}
				p = flowPolicy{useProxy: useProxy}
				ttl := h.tcpConntrackTTLShort
				if ttl <= 0 {
					ttl = 60 * time.Second
				}
				h.putCachedPolicy(now, key, p, ttl)
			}

			useProxy := p.useProxy
			if address != "" {
				host, _, _ := net.SplitHostPort(address)
				if host == "" {
					host = address
				}
				_, port, _ := net.SplitHostPort(dstAddr.String())
				address = net.JoinHostPort(strings.Trim(host, "[]"), port)
				ro.Host = address

				var buf bytes.Buffer
				if useProxy && h.forwarder != nil {
					baseRouter, ok := any(h.opts.Router).(interface {
						Options() *corechain.RouterOptions
					})
					if ok {
						c := xchain.NewChain("tungo-forwarder")
						c.AddHop(h.forwarder)
						bo := baseRouter.Options()
						proxyRouter := xchain.NewRouter(
							corechain.RetriesRouterOption(bo.Retries),
							corechain.TimeoutRouterOption(bo.Timeout),
							corechain.InterfaceRouterOption(bo.IfceName),
							corechain.NetnsRouterOption(bo.Netns),
							corechain.SockOptsRouterOption(bo.SockOpts),
							corechain.ResolverRouterOption(bo.Resolver),
							corechain.HostMapperRouterOption(bo.HostMapper),
							corechain.ChainRouterOption(c),
							corechain.LoggerRouterOption(log),
						)
						cc, err = proxyRouter.Dial(ictx.ContextWithBuffer(ctx, &buf), network, address)
					} else {
						cc, err = h.opts.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), network, address)
					}
				} else {
					cc, err = h.opts.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), network, address)
				}
				ro.Route = buf.String()
				if err != nil && !h.sniffingFallback {
					return nil, err
				}
			}

			if cc == nil {
				var buf bytes.Buffer
				cc, err = h.opts.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), network, dstAddr.String())
				ro.Route = buf.String()
				ro.Host = dstAddr.String()
			}

			if err == nil {
				ttl := h.tcpConntrackTTLLong
				if ttl <= 0 {
					ttl = 5 * time.Minute
				}
				h.touchPolicy(time.Now(), key, ttl)
			}

			return cc, err
		}

		dialTLS := func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
			return dial(ctx, network, address)
		}

		sniffer := &sniffing.Sniffer{
			Recorder:        h.recorder.Recorder,
			RecorderOptions: h.recorder.Options,
			ReadTimeout:     h.sniffingResponseTimeout,
		}

		conn = xnet.NewReadWriteConn(br, conn, conn)
		switch proto {
		case sniffing.ProtoHTTP:
			sniffer.HandleHTTP(ctx, network, conn,
				sniffing.WithService(h.service),
				sniffing.WithDial(dial),
				sniffing.WithDialTLS(dialTLS),
				sniffing.WithBypass(h.opts.Bypass),
				sniffing.WithRecorderObject(ro),
				sniffing.WithLog(log),
			)
			return
		case sniffing.ProtoTLS:
			sniffer.HandleTLS(ctx, network, conn,
				sniffing.WithService(h.service),
				sniffing.WithDial(dial),
				sniffing.WithDialTLS(dialTLS),
				sniffing.WithBypass(h.opts.Bypass),
				sniffing.WithRecorderObject(ro),
				sniffing.WithLog(log),
			)
			return
		}
	}

	useProxy := false
	if h.dec != nil {
		now := time.Now()
		if p, ok := h.getCachedPolicy(now, key); ok {
			useProxy = p.useProxy
		} else {
			appID, hostname := h.dec.ResolveMetadata(remoteIP.String(), dstIP.String(), int(id.RemotePort), int(id.LocalPort), "TCP")
			if hostname == "" {
				type domainLookup interface{ GetDomainsForIP(string) []string }
				if dl, ok := any(h.dec).(domainLookup); ok {
					if domains := dl.GetDomainsForIP(dstIP.String()); len(domains) > 0 {
						hostname = domains[0]
					}
				}
			}
			if d := h.dec.CheckTrafficRules(decision.RuleInput{
				SteamAppID: appID,
				DestHost:   dstIP.String(),
				DestPort:   int32(id.LocalPort),
				Protocol:   "TCP",
				DestDomain: hostname,
			}); d != nil {
				log.Debugf("traffic decision: action=%s rule=%s appID=%s dst=%s domain=%s", d.Action, d.RuleName, appID, dstAddr.String(), hostname)
				if strings.EqualFold(strings.TrimSpace(string(d.Action)), "PROXY") {
					useProxy = true
				}
			}
			p := flowPolicy{action: "", useProxy: useProxy}
			ttl := h.tcpConntrackTTLShort
			if ttl <= 0 {
				ttl = 60 * time.Second
			}
			h.putCachedPolicy(now, key, p, ttl)
		}
	}
	log.Debugf("traffic routing: useProxy=%t forwarderInjected=%t", useProxy, h.forwarder != nil)
	if useProxy && h.forwarder == nil {
		log.Warnf("traffic decision is PROXY but forwarder is nil; falling back to direct dial")
	}

	if h.opts.Bypass != nil &&
		h.opts.Bypass.Contains(ctx, network, dstAddr.String(), bypass.WithService(h.opts.Service)) {
		log.Debug("bypass: ", dstAddr)
		return
	}

	var buf bytes.Buffer
	var cc net.Conn
	// reuse the outer err so the deferred recorder sees failures
	if useProxy && h.forwarder != nil {
		baseRouter, ok := any(h.opts.Router).(interface {
			Options() *corechain.RouterOptions
		})
		if ok {
			bo := baseRouter.Options()
			if bo != nil {
				c := xchain.NewChain("tungo-forwarder")
				c.AddHop(h.forwarder)
				proxyRouter := xchain.NewRouter(
					corechain.RetriesRouterOption(bo.Retries),
					corechain.TimeoutRouterOption(bo.Timeout),
					corechain.InterfaceRouterOption(bo.IfceName),
					corechain.NetnsRouterOption(bo.Netns),
					corechain.SockOptsRouterOption(bo.SockOpts),
					corechain.ResolverRouterOption(bo.Resolver),
					corechain.HostMapperRouterOption(bo.HostMapper),
					corechain.ChainRouterOption(c),
					corechain.LoggerRouterOption(log),
				)
				cc, err = proxyRouter.Dial(ictx.ContextWithBuffer(ctx, &buf), network, dstAddr.String())
			} else {
				cc, err = h.opts.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), network, dstAddr.String())
			}
		} else {
			cc, err = h.opts.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), network, dstAddr.String())
		}
	} else {
		cc, err = h.opts.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), network, dstAddr.String())
	}
	ro.Route = buf.String()
	if err != nil {
		log.Errorf("dial %s: %v", dstAddr.String(), err)
		return
	}
	defer cc.Close()

	// We have a successfully established outbound connection; extend TTL.
	{
		ttl := h.tcpConntrackTTLLong
		if ttl <= 0 {
			ttl = 5 * time.Minute
		}
		h.touchPolicy(time.Now(), key, ttl)
	}

	ro.SrcAddr = cc.LocalAddr().String()
	log = log.WithFields(map[string]any{"src": ro.SrcAddr})

	t := time.Now()
	log.Infof("%s <-> %s", remoteAddr, dstAddr)
	{
		ttl := h.tcpConntrackTTLLong
		if ttl <= 0 {
			ttl = 5 * time.Minute
		}
		touch := func() {
			h.touchPolicy(time.Now(), key, ttl)
		}
		c1 := &touchConn{Conn: conn, touch: touch}
		c2 := &touchConn{Conn: cc, touch: touch}
		if e := xnet.Pipe(ctx, c1, c2); e != nil {
			// A few errors are expected during normal teardown (client cancel, half-close,
			// concurrent close races). Only surface actionable failures.
			msg := e.Error()
			benign := errors.Is(e, context.Canceled) || errors.Is(e, net.ErrClosed) ||
				strings.Contains(msg, "use of closed network connection") ||
				strings.Contains(msg, "websocket: close 1000") ||
				strings.Contains(msg, "websocket: close 1001")

			if !benign {
				log.Debugf("pipe error: %v", e)
				if err == nil {
					err = e
				}
			}
		}
	}
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", remoteAddr, dstAddr)
}

func (h *transportHandler) handleUDPConn(uc adapter.UDPConn) {
	defer uc.Close()

	id := uc.ID()

	remoteIP, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	dstIP, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())

	remoteAddr := netip.AddrPortFrom(remoteIP, id.RemotePort)
	dstAddr := netip.AddrPortFrom(dstIP, id.LocalPort)

	start := time.Now()

	sid := xid.New().String()
	ctx := xctx.ContextWithSid(context.Background(), xctx.Sid(sid))

	ro := &xrecorder.HandlerRecorderObject{
		Network:    "udp",
		Service:    h.opts.Service,
		RemoteAddr: remoteAddr.String(),
		DstAddr:    dstAddr.String(),
		ClientAddr: remoteAddr.String(),
		Host:       dstAddr.String(),
		SID:        sid,
		Time:       start,
	}

	log := h.opts.Logger.WithFields(map[string]any{
		"network": ro.Network,
		"remote":  ro.RemoteAddr,
		"dst":     ro.DstAddr,
		"sid":     ro.SID,
	})

	log.Debugf("%s <> %s", remoteAddr.String(), dstAddr.String())

	key := h.flowKeyUDP(remoteIP, dstIP, id.RemotePort, id.LocalPort)

	udpTTL := h.udpConntrackTTL
	if udpTTL <= 0 {
		udpTTL = 60 * time.Second
	}

	useProxy := false
	if p, ok := h.getCachedPolicy(time.Now(), key); ok {
		useProxy = p.useProxy
	} else if h.dec != nil {
		appID, hostname := h.dec.ResolveMetadata(remoteIP.String(), dstIP.String(), int(id.RemotePort), int(id.LocalPort), "UDP")
		if hostname == "" {
			type domainLookup interface{ GetDomainsForIP(string) []string }
			if dl, ok := any(h.dec).(domainLookup); ok {
				if domains := dl.GetDomainsForIP(dstIP.String()); len(domains) > 0 {
					hostname = domains[0]
				}
			}
		}
		if d := h.dec.CheckTrafficRules(decision.RuleInput{
			SteamAppID: appID,
			DestHost:   dstIP.String(),
			DestPort:   int32(id.LocalPort),
			Protocol:   "UDP",
			DestDomain: hostname,
		}); d != nil {
			log.Debugf("traffic decision: action=%s rule=%s appID=%s dst=%s domain=%s", d.Action, d.RuleName, appID, dstAddr.String(), hostname)
			if strings.EqualFold(strings.TrimSpace(string(d.Action)), "PROXY") {
				useProxy = true
			}
		}
		h.putCachedPolicy(time.Now(), key, flowPolicy{useProxy: useProxy}, udpTTL)
	}

	var err error
	var conn net.Conn = uc

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		ro.Duration = time.Since(start)
		if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
			log.Errorf("record: %v", err)
		}

		log.WithFields(map[string]any{
			"src":         ro.SrcAddr,
			"duration":    time.Since(start),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >< %s", remoteAddr.String(), dstAddr.String())
	}()

	cc, err := h.opts.Router.Dial(ctx, "udp", dstAddr.String())
	if err != nil {
		log.Errorf("dial %s: %v", dstAddr.String(), err)
		return
	}
	defer cc.Close()

	// Refresh UDP conntrack on activity.
	{
		touch := func() {
			h.touchPolicy(time.Now(), key, udpTTL)
		}
		conn = &touchConn{Conn: conn, touch: touch}
		cc = &touchConn{Conn: cc, touch: touch}
		h.touchPolicy(time.Now(), key, udpTTL)
	}

	ro.SrcAddr = cc.LocalAddr().String()
	log = log.WithFields(map[string]any{"src": ro.SrcAddr})

	t := time.Now()
	log.Infof("%s <-> %s", remoteAddr, dstAddr)
	h.pipePacketData(conn, cc, ro)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", remoteAddr, dstAddr)
}

func (h *transportHandler) pipePacketData(conn1, conn2 net.Conn, ro *xrecorder.HandlerRecorderObject) {
	timeout := h.udpTimeout
	if timeout <= 0 {
		timeout = udpSessionTimeout
	}

	bufferSize := h.udpBufferSize
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()

		buf := bufpool.Get(bufferSize)
		defer bufpool.Put(buf)

		copyPacketData(conn1, conn2, buf, h.sniffing, false, ro, timeout)
	}()
	go func() {
		defer wg.Done()

		buf := bufpool.Get(bufferSize)
		defer bufpool.Put(buf)

		copyPacketData(conn2, conn1, buf, h.sniffing, true, ro, timeout)
	}()
	wg.Wait()
}

func copyPacketData(dst, src net.Conn, buf []byte, sniffing bool, c2s bool, ro *xrecorder.HandlerRecorderObject, timeout time.Duration) error {
	isDNS := false

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, err := src.Read(buf)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil /* ignore I/O timeout */
		} else if err == io.EOF {
			return nil /* ignore EOF */
		} else if err != nil {
			return err
		}

		if n == 0 {
			return nil
		}

		if sniffing {
			// try to sniff DNS msg.
			{
				msg := &dns.Msg{}
				if msg.Unpack(buf[:n]) == nil && len(msg.Question) > 0 {
					if c2s {
						ro.Proto = "dns"
						ro.DNS = &xrecorder.DNSRecorderObject{
							ID:       int(msg.Id),
							Name:     msg.Question[0].Name,
							Class:    dns.Class(msg.Question[0].Qclass).String(),
							Type:     dns.Type(msg.Question[0].Qtype).String(),
							Question: msg.String(),
						}
					} else {
						if ro.DNS != nil {
							ro.DNS.Answer = msg.String()
						}
					}
					isDNS = true
				}
			}
		}

		if _, err = dst.Write(buf[:n]); err != nil {
			return err
		}
		dst.SetReadDeadline(time.Now().Add(timeout))

		if isDNS {
			return nil
		}
	}
}
