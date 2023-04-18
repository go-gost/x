package tun

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/logger"
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
		for {
			err := func() error {
				b := bufpool.Get(h.md.bufferSize)
				defer bufpool.Put(b)

				n, err := tun.Read(*b)
				if err != nil {
					return ErrTun
				}

				var src, dst net.IP
				if waterutil.IsIPv4((*b)[:n]) {
					header, err := ipv4.ParseHeader((*b)[:n])
					if err != nil {
						log.Warnf("parse ipv4 packet header: %v", err)
						return nil
					}
					src, dst = header.Src, header.Dst

					log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
						src, dst, ipProtocol(waterutil.IPv4Protocol((*b)[:n])),
						header.Len, header.TotalLen, header.ID, header.Flags)
				} else if waterutil.IsIPv6((*b)[:n]) {
					header, err := ipv6.ParseHeader((*b)[:n])
					if err != nil {
						log.Warnf("parse ipv6 packet header: %v", err)
						return nil
					}
					src, dst = header.Src, header.Dst

					log.Tracef("%s >> %s %s %d %d",
						src, dst,
						ipProtocol(waterutil.IPProtocol(header.NextHeader)),
						header.PayloadLen, header.TrafficClass)
				} else {
					log.Warn("unknown packet, discarded")
					return nil
				}

				addr := h.findRouteFor(dst, config.Routes...)
				if addr == nil {
					log.Debugf("no route for %s -> %s, packet discarded", src, dst)
					return nil
				}

				log.Debugf("find route: %s -> %s", dst, addr)

				if _, err := conn.WriteTo((*b)[:n], addr); err != nil {
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
		for {
			err := func() error {
				b := bufpool.Get(h.md.bufferSize)
				defer bufpool.Put(b)

				n, addr, err := conn.ReadFrom(*b)
				if err != nil {
					return err
				}
				if n > keepAliveHeaderLength && bytes.Equal((*b)[:4], magicHeader) {
					var peerIPs []net.IP
					data := (*b)[keepAliveHeaderLength:n]
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
						key := bytes.TrimRight((*b)[4:20], "\x00")
						for _, ip := range peerIPs {
							if ok = auther.Authenticate(ctx, ip.String(), string(key)); !ok {
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
				if waterutil.IsIPv4((*b)[:n]) {
					header, err := ipv4.ParseHeader((*b)[:n])
					if err != nil {
						log.Warnf("parse ipv4 packet header: %v", err)
						return nil
					}
					src, dst = header.Src, header.Dst

					log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
						src, dst, ipProtocol(waterutil.IPv4Protocol((*b)[:n])),
						header.Len, header.TotalLen, header.ID, header.Flags)
				} else if waterutil.IsIPv6((*b)[:n]) {
					header, err := ipv6.ParseHeader((*b)[:n])
					if err != nil {
						log.Warnf("parse ipv6 packet header: %v", err)
						return nil
					}
					src, dst = header.Src, header.Dst

					log.Tracef("%s > %s %s %d %d",
						src, dst,
						ipProtocol(waterutil.IPProtocol(header.NextHeader)),
						header.PayloadLen, header.TrafficClass)
				} else {
					log.Warn("unknown packet, discarded")
					return nil
				}

				if addr := h.findRouteFor(dst, config.Routes...); addr != nil {
					log.Debugf("find route: %s -> %s", dst, addr)

					_, err := conn.WriteTo((*b)[:n], addr)
					return err
				}

				if _, err := tun.Write((*b)[:n]); err != nil {
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
