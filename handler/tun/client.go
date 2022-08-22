package tun

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/logger"
	tun_util "github.com/go-gost/x/internal/util/tun"
	"github.com/songgao/water/waterutil"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// 4-byte magic header followed by 16-byte IP address
	keepAliveDataLength = 20
)

var (
	keepAliveHeader = []byte("GOST")
)

func (h *tunHandler) handleClient(ctx context.Context, conn net.Conn, addr net.Addr, config *tun_util.Config, log logger.Logger) error {
	ip, _, err := net.ParseCIDR(config.Net)
	if err != nil {
		return err
	}

	cc, err := h.router.Dial(ctx, addr.Network(), addr.String())
	if err != nil {
		return err
	}
	defer cc.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if h.md.keepAlivePeriod > 0 {
		go h.keepAlive(ctx, cc, ip)
	}

	return h.transportClient(conn, cc, config, log)
}

func (h *tunHandler) keepAlive(ctx context.Context, conn net.Conn, ip net.IP) {
	var keepAliveData [keepAliveDataLength]byte
	copy(keepAliveData[:4], keepAliveHeader) // magic header
	copy(keepAliveData[4:], ip.To16())

	ticker := time.NewTicker(h.md.keepAlivePeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if _, err := conn.Write(keepAliveData[:]); err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (h *tunHandler) transportClient(tun net.Conn, conn net.Conn, config *tun_util.Config, log logger.Logger) error {
	errc := make(chan error, 1)

	go func() {
		for {
			err := func() error {
				b := bufpool.Get(h.md.bufferSize)
				defer bufpool.Put(b)

				n, err := tun.Read(*b)
				if err != nil {
					return err
				}

				if waterutil.IsIPv4((*b)[:n]) {
					header, err := ipv4.ParseHeader((*b)[:n])
					if err != nil {
						log.Warn(err)
						return nil
					}

					log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
						header.Src, header.Dst, ipProtocol(waterutil.IPv4Protocol((*b)[:n])),
						header.Len, header.TotalLen, header.ID, header.Flags)
				} else if waterutil.IsIPv6((*b)[:n]) {
					header, err := ipv6.ParseHeader((*b)[:n])
					if err != nil {
						log.Warn(err)
						return nil
					}

					log.Tracef("%s >> %s %s %d %d",
						header.Src, header.Dst,
						ipProtocol(waterutil.IPProtocol(header.NextHeader)),
						header.PayloadLen, header.TrafficClass)
				} else {
					log.Warn("unknown packet, discarded")
					return nil
				}

				_, err = conn.Write((*b)[:n])
				return err
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

				n, err := conn.Read(*b)
				if err != nil {
					return err
				}

				if waterutil.IsIPv4((*b)[:n]) {
					header, err := ipv4.ParseHeader((*b)[:n])
					if err != nil {
						log.Warn(err)
						return nil
					}

					log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
						header.Src, header.Dst, ipProtocol(waterutil.IPv4Protocol((*b)[:n])),
						header.Len, header.TotalLen, header.ID, header.Flags)
				} else if waterutil.IsIPv6((*b)[:n]) {
					header, err := ipv6.ParseHeader((*b)[:n])
					if err != nil {
						log.Warn(err)
						return nil
					}

					log.Tracef("%s > %s %s %d %d",
						header.Src, header.Dst,
						ipProtocol(waterutil.IPProtocol(header.NextHeader)),
						header.PayloadLen, header.TrafficClass)
				} else {
					log.Warn("unknown packet, discarded")
					return nil
				}

				_, err = tun.Write((*b)[:n])
				return err
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
