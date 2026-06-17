package ss

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/utils"
	xctx "github.com/go-gost/x/ctx"
	ictx "github.com/go-gost/x/internal/ctx"
	"github.com/go-gost/x/internal/net/udp"
	"github.com/go-gost/x/internal/util/relay"
	"github.com/go-gost/x/internal/util/ss/none"
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
	cancels   sync.Map // session hash -> context.CancelFunc
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

	if h.options.Auth == nil {
		return errors.New("ss: auth is required")
	}

	method := h.options.Auth.Username()
	password, _ := h.options.Auth.Password()

	if strings.EqualFold(method, "none") || strings.EqualFold(method, "dummy") {
		c := core.ServerConfig{Cipher: none.Cipher, Users: h.md.users, UDPTimeout: time.Minute}
		h.udpServer = core.NewUDPServer(c)
		err = h.udpServer.Init()
		if err != nil {
			return err
		}
		h.tcpServer = core.NewTCPServer(c)
		err = h.tcpServer.Init()
		if err != nil {
			return err
		}
	} else {
		serverConfig, err := utils.NewServerConfig(method, password, h.md.users)
		if err != nil {
			return err
		}
		serverConfig.UDPTimeout = time.Minute
		h.udpServer = core.NewUDPServer(serverConfig)
		err = h.udpServer.Init()
		if err != nil {
			return err
		}

		h.tcpServer = core.NewTCPServer(serverConfig)
		err = h.tcpServer.Init()
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

		// UDP over TCP still behaves like a regular packet tunnel.
		var buf bytes.Buffer
		c, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), "udp", "")
		ro.Route = buf.String()
		if err != nil {
			log.Error(err)
			return err
		}
		defer c.Close()

		cc, ok := c.(net.PacketConn)
		if !ok {
			err := errors.New("ss: wrong connection type")
			log.Error(err)
			return err
		}

		r := udp.NewRelay(pc, cc).
			WithService(h.options.Service).
			WithBypass(h.options.Bypass).
			WithBufferSize(h.md.udpBufferSize).
			WithLogger(log)

		return r.Run(ctx)
	}

	return h.relayPacketUDP(ctx, h.udpServer.WrapConn(pc), ro, log)
}

func (h *ssuHandler) relayPacketUDP(ctx context.Context, src net.PacketConn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // cancel all per-session goroutines on exit

	bufferSize := h.md.udpBufferSize
	if bufferSize <= 0 {
		bufferSize = defaultBufferSize
	}

	b := make([]byte, bufferSize)
	for {
		n, addr, err := src.ReadFrom(b)
		if err != nil {
			return err
		}

		ctxAddr, ok := addr.(interface {
			Session() core.UDPSession
			ClientAddr() net.Addr
			TargetAddr() net.Addr
		})
		if !ok {
			return fmt.Errorf("ss: missing udp session context for addr %v", addr)
		}

		targetAddr := ctxAddr.TargetAddr()
		if ro.Host == "" && targetAddr != nil {
			ro.Host = targetAddr.String()
		}

		if h.options.Bypass != nil && targetAddr != nil && h.options.Bypass.Contains(ctx, "udp", targetAddr.String(), bypass.WithService(h.options.Service)) {
			log.Warn("bypass: ", targetAddr)
			return nil
		}

		if targetAddr == nil {
			return errors.New("ss: target address not available")
		}

		session := ctxAddr.Session()
		if session == nil {
			return fmt.Errorf("ss: udp session not found for addr %v", addr)
		}

		dstConn, err := h.packetConnForSession(ctx, src, session, ro, log)
		if err != nil {
			return err
		}

		if _, err = dstConn.WriteTo(b[:n], targetAddr); err != nil {
			return err
		}

		log.Tracef("%s >>> %s data: %d", dstConn.LocalAddr(), targetAddr, n)
	}
}

func (h *ssuHandler) packetConnForSession(ctx context.Context, src net.PacketConn, session core.UDPSession, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (net.PacketConn, error) {
	if cc, ok := h.connMap.Load(session.Hash()); ok {
		return cc.(net.PacketConn), nil
	}

	var buf bytes.Buffer
	c, err := h.options.Router.Dial(ictx.ContextWithBuffer(ctx, &buf), "udp", "")
	ro.Route = buf.String()
	if err != nil {
		log.Error(err)
		return nil, err
	}

	cc, ok := c.(net.PacketConn)
	if !ok {
		c.Close()
		err := errors.New("ss: wrong connection type")
		log.Error(err)
		return nil, err
	}

	if actual, loaded := h.connMap.LoadOrStore(session.Hash(), cc); loaded {
		c.Close()
		return actual.(net.PacketConn), nil
	}

	// Create a per-session cancel so the goroutine can be cleaned up
	// when relayPacketUDP exits (parent context cancelled) or on error.
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	h.cancels.Store(session.Hash(), sessionCancel)

	go func() {
		defer func() {
			sessionCancel()
			cc.Close()
			h.connMap.Delete(session.Hash())
			h.cancels.Delete(session.Hash())
		}()

		bufSize := h.md.udpBufferSize
		if bufSize <= 0 {
			bufSize = defaultBufferSize
		}
		b := make([]byte, bufSize)

		for {
			// Use a read deadline so the goroutine periodically checks
			// whether the parent context has been cancelled, instead of
			// blocking indefinitely on ReadFrom.
			cc.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, raddr, err := cc.ReadFrom(b)
			if err != nil {
				// If the parent context is done, exit silently.
				if sessionCtx.Err() != nil {
					return
				}
				// Timeout is expected — check context again before retrying.
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Warnf("failed to read response: %v", err)
				return
			}

			if h.options.Bypass != nil && h.options.Bypass.Contains(sessionCtx, "udp", raddr.String(), bypass.WithService(h.options.Service)) {
				log.Warn("bypass: ", raddr)
				return
			}

			if sessionCtx.Err() != nil {
				return
			}
			addr := core.NewUDPServerPacketAddr(raddr, net.UDPAddrFromAddrPort(session.ClientAddr()), session)
			if _, err = src.WriteTo(b[:n], addr); err != nil {
				log.Warnf("failed to write response to %v: %v", session.ClientAddr(), err)
				return
			}

			log.Tracef("%s <<< %s data: %d", cc.LocalAddr(), raddr, n)
		}
	}()

	return cc, nil
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

// Close cancels all per-session goroutines and closes cached connections.
func (h *ssuHandler) Close() error {
	h.cancels.Range(func(key, value any) bool {
		if cancel, ok := value.(context.CancelFunc); ok {
			cancel()
		}
		return true
	})
	h.connMap.Range(func(key, value any) bool {
		if cc, ok := value.(net.PacketConn); ok {
			cc.Close()
		}
		return true
	})
	return nil
}
