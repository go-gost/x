package ss

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/utils"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	"github.com/go-gost/x/internal/util/relay"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("ssu", NewHandler)
}

type ssuHandler struct {
	udpServer core.UDPServer
	tcpServer core.TCPServer // for udp over tcp
	connMap   sync.Map
	md        metadata
	options   handler.Options
	recorder  recorder.RecorderObject
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &ssuHandler{
		options: options,
	}
}

func (h *ssuHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}

	if h.options.Auth != nil {
		method := h.options.Auth.Username()
		password, _ := h.options.Auth.Password()

		serverConfig, err := utils.NewServerConfig(method, password, h.md.users)
		if err != nil {
			return err
		}
		h.udpServer = core.NewUDPServer(serverConfig, time.Duration(60*time.Second))
		err = h.udpServer.Init()
		if err != nil {
			return err
		}

		h.tcpServer = core.NewTCPServer(serverConfig)
		err = h.udpServer.Init()
		if err != nil {
			return err
		}
	}

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandler {
			h.recorder = ro
			break
		}
	}

	return
}

func (h *ssuHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Network:    "udp",
		Service:    h.options.Service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		SID:        xctx.SidFromContext(ctx).String(),
		Time:       start,
	}

	if srcAddr := xctx.SrcAddrFromContext(ctx); srcAddr != nil {
		ro.ClientAddr = srcAddr.String()
	}

	log := h.options.Logger.WithFields(map[string]any{
		"network": ro.Network,
		"remote":  conn.RemoteAddr().String(),
		"local":   conn.LocalAddr().String(),
		"client":  ro.ClientAddr,
		"sid":     ro.SID,
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		if err != nil {
			ro.Err = err.Error()
		}
		ro.Duration = time.Since(start)
		ro.Record(ctx, h.recorder.Recorder)

		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return rate_limiter.ErrRateLimit
	}

	pc, ok := conn.(net.PacketConn)
	if !ok {
		// UDP over TCP
		conn, err := h.tcpServer.WrapConn(conn)
		if err != nil {
			return err
		}

		// Note that UDPTunServerConn returns a wraped net.Conn, but it's behavior is not ordinary.
		// ReadFrom will return target addr of socks5 instead of normal remote addr
		// WriteTo will write data to original remote addr instead of the addr parameter passed to
		pc = relay.UDPTunServerConn(conn)

		return h.relayPacketTCP(ctx, pc, ro, log)
	} else {
		return h.relayPacketUDP(ctx, pc, ro, log)
	}
}

// UDP over TCP
func (h *ssuHandler) relayPacketTCP(ctx context.Context, src net.PacketConn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	bufferSize := h.md.udpBufferSize
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}

	b := bufpool.Get(bufferSize)
	defer bufpool.Put(b)

	var dstConn net.Conn
	defer func() {
		if dstConn != nil {
			dstConn.Close()
		}
	}()

	for {
		n, targetAddr, err := src.ReadFrom(b)
		if err != nil {
			return err
		}

		if ro.Host == "" {
			ro.Host = targetAddr.String()
		}

		if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, targetAddr.Network(), targetAddr.String(), bypass.WithService(h.options.Service)) {
			log.Warn("bypass: ", targetAddr)
			return nil
		}

		if dstConn == nil {
			// obtain a udp connection
			var buf bytes.Buffer
			dstConn, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), "udp", "") // UDP association
			ro.Route = buf.String()
			if err != nil {
				log.Error(err)
				return err
			}

			cc, ok := dstConn.(net.PacketConn)
			if !ok {
				err := errors.New("ss: wrong connection type")
				log.Error(err)
				return err
			}

			log.Infof("%s <-> %s", src.LocalAddr(), cc.LocalAddr())

			go func() {
				defer dstConn.Close()
				for {
					n, raddr, err := cc.ReadFrom(b)
					if err != nil {
						log.Warnf("failed to read response from %v: %v", raddr, err)
						return
					}

					if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, raddr.Network(), raddr.String(), bypass.WithService(h.options.Service)) {
						log.Warn("bypass: ", raddr)
						return
					}

					if _, err = src.WriteTo(b[:n], targetAddr); err != nil {
						log.Warnf("failed to write response from %v: %v", targetAddr, err)
						return
					}

					log.Tracef("%s <<< %s data: %d",
						cc.LocalAddr(), raddr, n)
				}
			}()
		}

		if _, err = dstConn.(net.PacketConn).WriteTo(b[:n], targetAddr); err != nil {
			return err
		}

		log.Tracef("%s >>> %s data: %d",
			dstConn.(net.PacketConn).LocalAddr(), targetAddr, n)
	}
}

// standard udp relay
// Dataflow: src (encrypted data) <-> dst (plaintext data)
func (h *ssuHandler) relayPacketUDP(ctx context.Context, src net.PacketConn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	bufferSize := h.md.udpBufferSize
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}

	b := bufpool.Get(bufferSize)
	defer bufpool.Put(b)

	for {
		n, addr, err := src.ReadFrom(b)
		if err != nil {
			return err
		}

		clientAddr, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return err
		}
		session, payload, err := h.udpServer.Inbound(b[:n], clientAddr)
		if err != nil {
			return err
		}

		targetAddr, err := net.ResolveUDPAddr("udp", session.Target().String())
		if ro.Host == "" {
			ro.Host = targetAddr.String()
		}

		if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, targetAddr.Network(), targetAddr.String(), bypass.WithService(h.options.Service)) {
			log.Warn("bypass: ", addr)
			return nil
		}
		if err != nil {
			return err
		}

		dstConn, ok := h.connMap.Load(session.Hash())
		if !ok {
			// obtain a udp connection
			var buf bytes.Buffer
			c, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), "udp", "") // UDP association
			ro.Route = buf.String()
			if err != nil {
				log.Error(err)
				return err
			}

			cc, ok := c.(net.PacketConn)
			if !ok {
				err := errors.New("ss: wrong connection type")
				log.Error(err)
				return err
			}
			h.connMap.Store(session.Hash(), c)

			dstConn = cc

			log.Infof("%s <-> %s", src.LocalAddr(), cc.LocalAddr())

			go func() {
				defer func() {
					c.Close()
					h.connMap.Delete(session.Hash())
				}()

				for {
					n, raddr, err := dstConn.(net.PacketConn).ReadFrom(b)
					if err != nil {
						log.Warnf("failed to read response: %v", err)
						return
					}

					clientAddr := session.ClientAddr()
					if h.options.Bypass != nil && h.options.Bypass.Contains(ctx, raddr.Network(), raddr.String(), bypass.WithService(h.options.Service)) {
						log.Warn("bypass: ", raddr)
						return
					}
					encrypted, err := h.udpServer.Outbound(b[:n], session)
					if _, err = src.WriteTo(encrypted, net.UDPAddrFromAddrPort(clientAddr)); err != nil {
						log.Warnf("failed to write response to %v: %v", clientAddr, err)
						return
					}

					log.Tracef("%s <<< %s data: %d",
						dstConn.(net.PacketConn).LocalAddr(), raddr, n)
				}
			}()
		}

		if n, err = dstConn.(net.PacketConn).WriteTo(payload, targetAddr); err != nil {
			return err
		}

		log.Tracef("%s >>> %s data: %d",
			dstConn.(net.PacketConn).LocalAddr(), targetAddr, n)
	}
}

func (h *ssuHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}
