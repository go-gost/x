package tun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/common/bufpool"
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

func (h *tunHandler) handleClient(ctx context.Context, conn net.Conn, network string, raddr string, config *tun_util.Config, log logger.Logger) error {
	var ips []net.IP
	for _, net := range config.Net {
		ips = append(ips, net.IP)
	}
	if len(ips) == 0 {
		return ErrInvalidNet
	}

	for {
		err := func() error {
			cc, err := h.options.Router.Dial(ctx, network, raddr)
			if err != nil {
				return err
			}
			defer cc.Close()

			// The registration handshake always runs. It is how the far side's
			// tun server learns which addresses this device holds, and it is
			// the only thing that tells it — a server routes by destination
			// address, and this is the sole source of that mapping. Without it
			// the link is one-way: traffic leaves, and nothing can come back.
			//
			// A configured keepalive period only decides whether the handshake
			// then repeats, which matters against a server reached over UDP:
			// UDP is connectionless, so silence is the only signal that a peer
			// has left, and a repeat is what lets a route expire. On a p2p link
			// the period buys nothing — closing the stream says the peer is
			// gone — so a one-shot is the whole of it there.
			iterCtx, iterCancel := context.WithCancel(ctx)
			defer iterCancel()

			go h.keepalive(iterCtx, cc, ips)

			return h.transportClient(ctx, conn, cc, log)
		}()
		if errors.Is(err, ErrTun) {
			return err
		}

		log.Error(err)
		time.Sleep(time.Second)
	}
}

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

func (h *tunHandler) transportClient(ctx context.Context, tun io.ReadWriter, conn net.Conn, log logger.Logger) error {
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
					// %w, not %s: a device closed under the reader must stay
					// recognisable as a closed device, or an intentional stop
					// reads as a failure all the way up.
					return fmt.Errorf("%w: read: %w", ErrTun, err)
				}

				if waterutil.IsIPv4(b[:n]) {
					header, err := ipv4.ParseHeader(b[:n])
					if err != nil {
						log.Warn(err)
						return nil
					}

					if log.IsLevelEnabled(logger.TraceLevel) {
						log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
							header.Src, header.Dst, xip.Protocol(waterutil.IPv4Protocol(b[:n])),
							header.Len, header.TotalLen, header.ID, header.Flags)
					}
				} else if waterutil.IsIPv6(b[:n]) {
					header, err := ipv6.ParseHeader(b[:n])
					if err != nil {
						log.Warn(err)
						return nil
					}

					if log.IsLevelEnabled(logger.TraceLevel) {
						log.Tracef("%s >> %s %s %d %d",
							header.Src, header.Dst,
							xip.Protocol(waterutil.IPProtocol(header.NextHeader)),
							header.PayloadLen, header.TrafficClass)
					}
				} else {
					log.Warnf("unknown packet, discarded(%d)", n)
					return nil
				}

				_, err = conn.Write(b[:n])
				return err
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
				n, err := conn.Read(b[:])
				if err != nil {
					return err
				}

				// Any inbound byte proves the tunnel is alive: refresh the liveness
				// deadline before interpreting the packet. Relying on the keepalive
				// echo alone (which a transient channel hiccup can drop) would redial
				// a healthy tunnel after 3×period.
				if h.md.keepAlivePeriod > 0 {
					conn.SetReadDeadline(time.Now().Add(h.md.keepAlivePeriod * 3))
				}

				// A registration handshake or keepalive echo is protocol, not a
				// packet, so it never belongs on the device. The client does not
				// route by address — only the hub reads it, on its own side.
				// Without this guard a 20+N*16-byte registration frame from the
				// peer is misread as IPv4 ('G' is 0x47) and gets written into
				// the kernel device as junk. The hub and the socket server
				// already filter this shape; the client must too.
				if n >= keepAliveHeaderLength && bytes.Equal(b[:4], magicHeader) {
					if n == keepAliveHeaderLength {
						log.Debugf("keepalive received at %v", net.IP(b[4:20]))
					} else {
						log.Debugf("keepalive frame (%d bytes, %d address(es)) discarded", n, (n-keepAliveHeaderLength)/net.IPv6len)
					}
					return nil
				}

				if waterutil.IsIPv4(b[:n]) {
					header, err := ipv4.ParseHeader(b[:n])
					if err != nil {
						log.Warn(err)
						return nil
					}

					if log.IsLevelEnabled(logger.TraceLevel) {
						log.Tracef("%s >> %s %-4s %d/%-4d %-4x %d",
							header.Src, header.Dst, xip.Protocol(waterutil.IPv4Protocol(b[:n])),
							header.Len, header.TotalLen, header.ID, header.Flags)
					}
				} else if waterutil.IsIPv6(b[:n]) {
					header, err := ipv6.ParseHeader(b[:n])
					if err != nil {
						log.Warn(err)
						return nil
					}

					if log.IsLevelEnabled(logger.TraceLevel) {
						log.Tracef("%s > %s %s %d %d",
							header.Src, header.Dst,
							xip.Protocol(waterutil.IPProtocol(header.NextHeader)),
							header.PayloadLen, header.TrafficClass)
					}
				} else {
					log.Warn("unknown packet, discarded")
					return nil
				}

				if _, err = tun.Write(b[:n]); err != nil {
					return fmt.Errorf("%w: write: %s", ErrTun, err.Error())
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
