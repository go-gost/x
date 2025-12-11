package tun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AeroCore-IO/avionics/pkg/decision"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	xip "github.com/go-gost/x/internal/net/ip"
	tun_util "github.com/go-gost/x/internal/util/tun"
	"github.com/songgao/water/waterutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// 4-byte magic header followed by 16-byte key.
	keepAliveHeaderLength = 20
)

var (
	magicHeader = []byte("GOST")
)

func (h *tunHandler) keepalive(ctx context.Context, conn net.Conn, ips []net.IP) {
	// handshake
	keepAliveData := bufpool.Get(keepAliveHeaderLength + len(ips)*net.IPv6len)
	defer bufpool.Put(keepAliveData)

	copy(keepAliveData[:4], magicHeader) // magic header
	copy(keepAliveData[4:20], []byte(h.md.passphrase))
	pos := 20
	for _, ip := range ips {
		copy(keepAliveData[pos:pos+net.IPv6len], ip.To16())
		pos += net.IPv6len
	}
	if _, err := conn.Write(keepAliveData); err != nil {
		return
	}

	if h.md.keepAlivePeriod <= 0 {
		return
	}
	conn.SetReadDeadline(time.Now().Add(h.md.keepAlivePeriod * 3))

	ticker := time.NewTicker(h.md.keepAlivePeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if _, err := conn.Write(keepAliveData); err != nil {
				return
			}
			h.options.Logger.Debugf("keepalive sended")
		case <-ctx.Done():
			return
		}
	}
}

type clientSession struct {
	key     string
	node    *chain.Node
	network string
	raddr   string
	conn    net.Conn
	writeCh chan []byte
	log     logger.Logger
	cancel  context.CancelFunc
	closed  chan struct{}
	once    sync.Once
}

func (s *clientSession) close() {
	s.once.Do(func() {
		close(s.closed)
		if s.cancel != nil {
			s.cancel()
		}
		if s.conn != nil {
			s.conn.Close()
		}
		close(s.writeCh)
	})
}

func (s *clientSession) reportError(errc chan<- error, err error) {
	if err == nil {
		return
	}
	select {
	case errc <- err:
	default:
	}
	s.close()
}

func (s *clientSession) writeLoop(ctx context.Context, errc chan<- error) {
	defer s.close()
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-s.writeCh:
			if !ok {
				return
			}
			if len(pkt) == 0 {
				continue
			}
			if _, err := s.conn.Write(pkt); err != nil {
				s.reportError(errc, err)
				return
			}
		}
	}
}

func (s *clientSession) readLoop(ctx context.Context, tun io.Writer, tunMu *sync.Mutex, keepAlivePeriod time.Duration, errc chan<- error) {
	defer s.close()
	var b [MaxMessageSize]byte
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := s.conn.Read(b[:])
		if err != nil {
			s.reportError(errc, err)
			return
		}

		if n == keepAliveHeaderLength && bytes.Equal(b[:4], magicHeader) {
			ip := net.IP(b[4:20])
			s.log.Debugf("keepalive received at %v via %s", ip, s.raddr)

			if keepAlivePeriod > 0 {
				_ = s.conn.SetReadDeadline(time.Now().Add(keepAlivePeriod * 3))
			}
			continue
		}

		if waterutil.IsIPv4(b[:n]) {
			header, _ := ipv4.ParseHeader(b[:n])
			if s.log.IsLevelEnabled(logger.TraceLevel) {
				s.log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
					header.Src, header.Dst, xip.Protocol(waterutil.IPv4Protocol(b[:n])),
					header.Len, header.TotalLen, header.ID, header.Flags)
			}
		} else if waterutil.IsIPv6(b[:n]) {
			header, _ := ipv6.ParseHeader(b[:n])
			if s.log.IsLevelEnabled(logger.TraceLevel) {
				s.log.Tracef("%s >> %s %s %d %d",
					header.Src, header.Dst,
					xip.Protocol(waterutil.IPProtocol(header.NextHeader)),
					header.PayloadLen, header.TrafficClass)
			}
		}

		tunMu.Lock()
		_, err = tun.Write(b[:n])
		tunMu.Unlock()
		if err != nil {
			s.reportError(errc, fmt.Errorf("%w: write: %s", ErrTun, err.Error()))
			return
		}
	}
}

func (h *tunHandler) handleClient(ctx context.Context, conn net.Conn, config *tun_util.Config, log logger.Logger) error {
	ips := collectIPs(config.Net)
	if len(ips) == 0 {
		return ErrInvalidNet
	}

	var fallback *chain.Node
	if h.hop != nil {
		fallback = h.hop.Select(ctx)
	}

	for {
		err := h.runClient(ctx, conn, ips, fallback, log, config)
		if errors.Is(err, ErrTun) {
			return err
		}

		if err != nil {
			log.Error(err)
		}
		time.Sleep(time.Second)
	}
}

func (h *tunHandler) runClient(ctx context.Context, tun net.Conn, ips []net.IP, fallback *chain.Node, log logger.Logger, config *tun_util.Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sessions := make(map[string]*clientSession)
	var sessMu sync.Mutex
	errc := make(chan error, 1)
	tunMu := &sync.Mutex{}

	go h.dispatchPackets(ctx, tun, ips, fallback, log, tunMu, sessions, &sessMu, errc, config)

	err := <-errc
	cancel()

	sessMu.Lock()
	for key, s := range sessions {
		s.close()
		delete(sessions, key)
	}
	sessMu.Unlock()

	return err
}

func (h *tunHandler) dispatchPackets(
	ctx context.Context,
	tun net.Conn,
	ips []net.IP,
	fallback *chain.Node,
	log logger.Logger,
	tunMu *sync.Mutex,
	sessions map[string]*clientSession,
	sessMu *sync.Mutex,
	errc chan<- error,
	config *tun_util.Config,
) {
	var b [MaxMessageSize]byte
	for {
		n, err := tun.Read(b[:])
		if err != nil {
			errc <- fmt.Errorf("%w: read: %s", ErrTun, err.Error())
			return
		}

		src, dst, sport, dport, proto, ok := parsePacketMetadata(b[:n], log)
		if !ok {
			continue
		}

		if h.dec != nil {
			appID, hostname := h.dec.ResolveMetadata(src.String(), dst.String(), sport, dport, strings.ToUpper(proto))
			deci := h.dec.CheckTrafficRules(decision.RuleInput{
				SteamAppID: appID,
				DestHost:   dst.String(),
				DestPort:   int32(dport),
				Protocol:   strings.ToUpper(proto),
				DestDomain: hostname,
			})

			switch deci.Action {
			case decision.ActionBlock:
				log.Debugf("packet blocked by decision: %s:%d/%s", dst, dport, proto)
				continue
			case decision.ActionDirect:
				log.Debugf("packet allowed direct (not proxied): %s:%d/%s", dst, dport, proto)
				pkt := make([]byte, n)
				copy(pkt, b[:n])
				if err := h.forwardDirect(ctx, tun, config, log, tunMu, pkt); err != nil {
					log.Errorf("direct forward failed: %v", err)
				}
				continue
			case decision.ActionProxy:
				// proceed to proxy
			default:
				// default fallthrough to proxy
			}
		}

		node := h.selectTargetForPacket(ctx, dst, proto)
		if node == nil {
			node = fallback
		}
		if node == nil {
			errc <- errors.New("tun: no available node for packet")
			return
		}

		session, er := h.ensureSession(ctx, node, ips, tun, tunMu, log, sessions, sessMu, errc)
		if er != nil {
			errc <- er
			return
		}

		pkt := make([]byte, n)
		copy(pkt, b[:n])

		select {
		case session.writeCh <- pkt:
		case <-ctx.Done():
			errc <- ctx.Err()
			return
		}
	}
}

func (h *tunHandler) ensureSession(
	ctx context.Context,
	node *chain.Node,
	ips []net.IP,
	tun io.Writer,
	tunMu *sync.Mutex,
	log logger.Logger,
	sessions map[string]*clientSession,
	sessMu *sync.Mutex,
	errc chan<- error,
) (*clientSession, error) {
	key := sessionKeyForNode(node)

	sessMu.Lock()
	s := sessions[key]
	sessMu.Unlock()
	if s != nil {
		return s, nil
	}

	network := "udp"
	raddr := node.Addr
	if _, _, err := net.SplitHostPort(raddr); err != nil {
		network = "ip"
	}

	cctx, cancel := context.WithCancel(ctx)
	cc, err := h.options.Router.Dial(cctx, network, raddr)
	if err != nil {
		cancel()
		return nil, err
	}

	s = &clientSession{
		key:     key,
		node:    node,
		network: network,
		raddr:   raddr,
		conn:    cc,
		writeCh: make(chan []byte, 64),
		log: log.WithFields(map[string]any{
			"dst":  fmt.Sprintf("%s/%s", raddr, network),
			"node": node.Name,
		}),
		cancel: cancel,
		closed: make(chan struct{}),
	}

	if network == "udp" {
		go h.keepalive(cctx, cc, ips)
	}

	go s.writeLoop(cctx, errc)
	go s.readLoop(cctx, tun, tunMu, h.md.keepAlivePeriod, errc)

	sessMu.Lock()
	sessions[key] = s
	sessMu.Unlock()

	return s, nil
}

func (h *tunHandler) selectTargetForPacket(ctx context.Context, dst net.IP, proto string) *chain.Node {
	if h.hop == nil {
		return nil
	}

	network := strings.ToLower(proto)
	if network == "" {
		network = "ip"
	}

	opts := []hop.SelectOption{
		hop.NetworkSelectOption(network),
		hop.AddrSelectOption(dst.String()),
		hop.HostSelectOption(dst.String()),
	}
	if proto != "" {
		opts = append(opts, hop.ProtocolSelectOption(strings.ToLower(proto)))
	}

	return h.hop.Select(ctx, opts...)
}

func (h *tunHandler) forwardDirect(ctx context.Context, tun net.Conn, config *tun_util.Config, log logger.Logger, tunMu *sync.Mutex, pkt []byte) error {
	if config == nil {
		return errors.New("direct: missing tun config")
	}
	if h.direct == nil {
		h.direct = newDirectForwarder()
	}
	if err := h.direct.start(ctx, tun, config.MTU, log, &h.options, tunMu); err != nil {
		return err
	}
	if ok := h.direct.inject(pkt); !ok {
		return fmt.Errorf("direct: forwarder busy")
	}
	return nil
}

func parsePacketMetadata(data []byte, log logger.Logger) (src, dst net.IP, sport, dport int, proto string, ok bool) {
	if waterutil.IsIPv4(data) {
		header, err := ipv4.ParseHeader(data)
		if err != nil {
			log.Warn(err)
			return
		}
		src = header.Src
		dst = header.Dst
		proto = xip.Protocol(waterutil.IPv4Protocol(data))
		sport, dport = parseL4Ports(data, int(header.Len), int(header.Protocol))
		if log.IsLevelEnabled(logger.TraceLevel) {
			log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
				header.Src, header.Dst, proto,
				header.Len, header.TotalLen, header.ID, header.Flags)
		}
		return src, dst, sport, dport, proto, true
	}

	if waterutil.IsIPv6(data) {
		header, err := ipv6.ParseHeader(data)
		if err != nil {
			log.Warn(err)
			return
		}
		src = header.Src
		dst = header.Dst
		proto = xip.Protocol(waterutil.IPProtocol(header.NextHeader))
		sport, dport = parseL4Ports(data, ipv6.HeaderLen, int(header.NextHeader))
		if log.IsLevelEnabled(logger.TraceLevel) {
			log.Tracef("%s >> %s %s %d %d",
				header.Src, header.Dst, proto,
				header.PayloadLen, header.TrafficClass)
		}
		return src, dst, sport, dport, proto, true
	}

	log.Warnf("unknown packet, discarded(%d)", len(data))
	return
}

// parseL4Ports extracts source and destination ports for TCP/UDP packets when possible.
func parseL4Ports(pkt []byte, ipHeaderLen int, l4Proto int) (sport, dport int) {
	if len(pkt) < ipHeaderLen+4 {
		return 0, 0
	}
	switch l4Proto {
	case 6, 17: // TCP=6, UDP=17
		sport = int(pkt[ipHeaderLen])<<8 | int(pkt[ipHeaderLen+1])
		dport = int(pkt[ipHeaderLen+2])<<8 | int(pkt[ipHeaderLen+3])
		return
	default:
		return 0, 0
	}
}

func collectIPs(nets []net.IPNet) []net.IP {
	ips := make([]net.IP, 0, len(nets))
	for _, ipnet := range nets {
		ips = append(ips, ipnet.IP)
	}
	return ips
}

func sessionKeyForNode(node *chain.Node) string {
	if node == nil {
		return ""
	}
	if node.Name != "" {
		return node.Name
	}
	return node.Addr
}
