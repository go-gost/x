package tun

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/router"
	xip "github.com/go-gost/x/internal/net/ip"
	tun_util "github.com/go-gost/x/internal/util/tun"
	"github.com/songgao/water/waterutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func (h *tunHandler) handleServer(ctx context.Context, conn net.Conn, config *tun_util.Config, log logger.Logger) error {
	for {
		err := func() error {
			pc, err := net.ListenPacket(conn.LocalAddr().Network(), conn.LocalAddr().String())
			if err != nil {
				return err
			}
			defer pc.Close()

			return h.transportServer(ctx, conn, pc, config, log)
		}()
		if errors.Is(err, ErrTun) {
			return err
		}

		log.Error(err)
		time.Sleep(time.Second)
	}
}

func (h *tunHandler) transportServer(ctx context.Context, tun io.ReadWriter, conn net.PacketConn, config *tun_util.Config, log logger.Logger) error {
	c, cancel := context.WithCancel(ctx)
	defer cancel()

	errc := make(chan error, 2)

	go func() {
		var b [MaxMessageSize]byte
		for {
			select {
			case <-c.Done():
				errc <- c.Err()
				return
			default:
			}

			err := func() error {
				n, err := tun.Read(b[:])
				if err != nil {
					return ErrTun
				}
				if n == 0 {
					return nil
				}

				var src, dst net.IP
				if waterutil.IsIPv4(b[:n]) {
					header, err := ipv4.ParseHeader(b[:n])
					if err != nil {
						log.Warnf("parse ipv4 packet header: %v", err)
						return nil
					}
					src, dst = header.Src, header.Dst

					if log.IsLevelEnabled(logger.TraceLevel) {
						log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
							src, dst, xip.Protocol(waterutil.IPv4Protocol(b[:n])),
							header.Len, header.TotalLen, header.ID, header.Flags)
					}
				} else if waterutil.IsIPv6(b[:n]) {
					header, err := ipv6.ParseHeader(b[:n])
					if err != nil {
						log.Warnf("parse ipv6 packet header: %v", err)
						return nil
					}
					src, dst = header.Src, header.Dst

					if log.IsLevelEnabled(logger.TraceLevel) {
						log.Tracef("%s >> %s %s %d %d",
							src, dst,
							xip.Protocol(waterutil.IPProtocol(header.NextHeader)),
							header.PayloadLen, header.TrafficClass)
					}
				} else {
					log.Warnf("unknown packet, discarded(%d)", n)
					return nil
				}

				name, ok := h.findRouteFor(ctx, dst, config.Router)
				if !ok {
					log.Debugf("no route for %s -> %s, packet discarded", src, dst)
					return nil
				}
				addr, err := resolveUDPAddr(name)
				if err != nil {
					// Unreachable for a socket peer: the table only ever holds
					// an address a UDP conn reported, so it always resolves.
					log.Warnf("route %s: %v", name, err)
					return nil
				}

				log.Debugf("find route: %s -> %s", dst, addr)

				if _, err := conn.WriteTo(b[:n], addr); err != nil {
					return err
				}
				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	go func() {
		var b [MaxMessageSize]byte
		for {
			select {
			case <-c.Done():
				errc <- c.Err()
				return
			default:
			}

			err := func() error {
				n, addr, err := conn.ReadFrom(b[:])
				if err != nil {
					return err
				}
				if n == 0 {
					return nil
				}
				if n > keepAliveHeaderLength && bytes.Equal(b[:4], magicHeader) {
					from := addr.String()
					if _, ok := h.router.onKeepalive(ctx, b[:n], from, config.Net); !ok {
						return nil
					}

					// onKeepalive registers what the frame claimed, which is
					// right for a socket peer and wrong for a p2p one: a p2p hub
					// reaches its peer over the single link the tunnel gives it,
					// so the route it delivers on collapses onto :: whatever
					// address the peer claimed on its own tun. The collapse
					// cannot live in peerTable.set — that is transport
					// behavior, and the socket path shares the table and needs a
					// peer's own address as its key — so it stays here, the
					// caller that knows which transport it is.
					//
					// The addresses onKeepalive also registered are left alone:
					// a p2p lookup only ever asks for :: (findRouteFor collapses
					// the same way), so nothing can read them, and dropPeer is
					// how the p2p transport reclaims a peer by name when its
					// stream ends.
					if h.md.p2p {
						h.router.set(net.IPv6zero, from)
					}

					// The reply is the caller's half of the handshake: the table
					// parses and registers but never writes, because the answer has
					// to go back over the transport this frame arrived on. Drop it
					// and every keepalive:true spoke misses the echo its read
					// deadline is refreshed from, then redials.
					addrPort, err := netip.ParseAddrPort(from)
					if err != nil {
						log.Warnf("keepalive from %v: %v", addr, err)
						return nil
					}
					var reply [keepAliveHeaderLength]byte
					copy(reply[:4], magicHeader)
					a16 := addrPort.Addr().As16()
					copy(reply[4:], a16[:])
					if _, err := conn.WriteTo(reply[:], addr); err != nil {
						log.Warnf("keepalive to %v: %v", addr, err)
						return nil
					}
					return nil
				}

				var src, dst net.IP
				if waterutil.IsIPv4(b[:n]) {
					header, err := ipv4.ParseHeader(b[:n])
					if err != nil {
						log.Warnf("parse ipv4 packet header: %v", err)
						return nil
					}
					src, dst = header.Src, header.Dst

					if log.IsLevelEnabled(logger.TraceLevel) {
						log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
							src, dst, xip.Protocol(waterutil.IPv4Protocol(b[:n])),
							header.Len, header.TotalLen, header.ID, header.Flags)
					}
				} else if waterutil.IsIPv6(b[:n]) {
					header, err := ipv6.ParseHeader(b[:n])
					if err != nil {
						log.Warnf("parse ipv6 packet header: %v", err)
						return nil
					}
					src, dst = header.Src, header.Dst

					if log.IsLevelEnabled(logger.TraceLevel) {
						log.Tracef("%s > %s %s %d %d",
							src, dst,
							xip.Protocol(waterutil.IPProtocol(header.NextHeader)),
							header.PayloadLen, header.TrafficClass)
					}
				} else {
					log.Warnf("unknown packet, discarded(%d): % x", n, b[:n])
					return nil
				}

				// Not a p2p hub: a peer that has claimed dst is the next hop for
				// this packet. No route, so the packet is the device's.
				if !h.md.p2p {
					if name, ok := h.findRouteFor(ctx, dst, config.Router); ok {
						addr, err := resolveUDPAddr(name)
						if err != nil {
							// Unreachable for a socket peer — the table only
							// ever holds the address a UDP conn reported. Read as
							// no route rather than dropped, which is what this
							// loop has always done when a peer cannot be named.
							log.Warnf("route %s: %v", name, err)
						} else {
							log.Debugf("find route: %s -> %s", dst, addr)

							_, err = conn.WriteTo(b[:n], addr)
							return err
						}
					}
				}

				if _, err := tun.Write(b[:n]); err != nil {
					return ErrTun
				}
				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	return collectFirstError(errc, cancel)
}

// findRouteFor resolves dst to the name of the peer that claimed it, falling
// back to the peer on dst's route's gateway. The name is a transport-neutral
// "host:port" here; only the caller knows how to reach one.
func (h *tunHandler) findRouteFor(ctx context.Context, dst net.IP, router router.Router) (string, bool) {
	if h.md.p2p {
		dst = net.IPv6zero
		router = nil
	}

	if name, ok := h.router.lookup(dst); ok {
		return name, true
	}

	if router == nil {
		return "", false
	}

	if route := router.GetRoute(ctx, dst.String()); route != nil {
		if gw := net.ParseIP(route.Gateway); gw != nil {
			if name, ok := h.router.lookup(gw); ok {
				return name, true
			}
		}
	}
	return "", false
}

// resolveUDPAddr turns a route's name back into the address it was stored as.
// Resolved per delivery rather than cached: it is a parse and an allocation
// against a device read that already cost a syscall, and an address changes
// when a peer's source port moves, so a cache would cost more to keep correct
// than it saves.
func resolveUDPAddr(name string) (net.Addr, error) {
	return net.ResolveUDPAddr("udp", name)
}
