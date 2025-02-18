package tun

import (
	"bytes"
	"context"
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
		if err == ErrTun {
			return err
		}

		log.Error(err)
		time.Sleep(time.Second)
	}
}

func (h *tunHandler) transportServer(ctx context.Context, tun io.ReadWriter, conn net.PacketConn, config *tun_util.Config, log logger.Logger) error {
	errc := make(chan error, 1)

	go func() {
		var b [MaxMessageSize]byte
		for {
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

				addr := h.findRouteFor(ctx, dst, config.Router)
				if addr == nil {
					log.Debugf("no route for %s -> %s, packet discarded", src, dst)
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
			err := func() error {
				n, addr, err := conn.ReadFrom(b[:])
				if err != nil {
					return err
				}
				if n == 0 {
					return nil
				}
				if n > keepAliveHeaderLength && bytes.Equal(b[:4], magicHeader) {
					var peerIPs []net.IP
					data := b[keepAliveHeaderLength:n]
					if len(data)%net.IPv6len == 0 {
						for len(data) > 0 {
							peerIPs = append(peerIPs, net.IP(data[:net.IPv6len]))
							data = data[net.IPv6len:]
						}
					}
					if len(peerIPs) == 0 {
						return nil
					}

					for _, net := range config.Net {
						for _, ip := range peerIPs {
							if ip.Equal(net.IP.To16()) {
								return nil
							}
						}
					}

					if auther := h.options.Auther; auther != nil {
						ok := true
						key := bytes.TrimRight(b[4:20], "\x00")
						for _, ip := range peerIPs {
							if _, ok = auther.Authenticate(ctx, ip.String(), string(key)); !ok {
								break
							}
						}
						if !ok {
							log.Debugf("keepalive from %v => %v, auth FAILED", addr, peerIPs)
							return nil
						}
					}

					log.Debugf("keepalive from %v => %v", addr, peerIPs)

					addrPort, err := netip.ParseAddrPort(addr.String())
					if err != nil {
						log.Warnf("keepalive from %v: %v", addr, err)
						return nil
					}
					var keepAliveData [keepAliveHeaderLength]byte
					copy(keepAliveData[:4], magicHeader) // magic header
					a16 := addrPort.Addr().As16()
					copy(keepAliveData[4:], a16[:])

					if _, err := conn.WriteTo(keepAliveData[:], addr); err != nil {
						log.Warnf("keepalive to %v: %v", addr, err)
						return nil
					}

					for _, ip := range peerIPs {
						h.updateRoute(ip, addr, log)
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

				if !h.md.p2p {
					if addr := h.findRouteFor(ctx, dst, config.Router); addr != nil {
						log.Debugf("find route: %s -> %s", dst, addr)

						_, err := conn.WriteTo(b[:n], addr)
						return err
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

	err := <-errc
	if err != nil && err == io.EOF {
		err = nil
	}
	return err
}

func (h *tunHandler) updateRoute(ip net.IP, addr net.Addr, log logger.Logger) {
	if h.md.p2p {
		ip = net.IPv6zero
	}
	rkey := ipToTunRouteKey(ip)
	if actual, loaded := h.routes.LoadOrStore(rkey, addr); loaded {
		if actual.(net.Addr).String() != addr.String() {
			h.routes.Store(rkey, addr)
			log.Debugf("update route: %s -> %s (old %s)",
				ip, addr, actual.(net.Addr))
		}
	} else {
		log.Debugf("new route: %s -> %s", ip, addr)
	}
}

func (h *tunHandler) findRouteFor(ctx context.Context, dst net.IP, router router.Router) net.Addr {
	if h.md.p2p {
		dst = net.IPv6zero
		router = nil
	}

	if v, ok := h.routes.Load(ipToTunRouteKey(dst)); ok {
		return v.(net.Addr)
	}

	if router == nil {
		return nil
	}

	if route := router.GetRoute(ctx, dst.String()); route != nil {
		if gw := net.ParseIP(route.Gateway); gw != nil {
			if v, ok := h.routes.Load(ipToTunRouteKey(gw)); ok {
				return v.(net.Addr)
			}
		}
	}
	return nil
}
