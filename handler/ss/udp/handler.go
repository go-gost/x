package ss

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/internal/util/relay"
	"github.com/go-gost/x/internal/util/ss"
	"github.com/go-gost/x/registry"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

func init() {
	registry.HandlerRegistry().Register("ssu", NewHandler)
}

type ssuHandler struct {
	cipher  core.Cipher
	router  *chain.Router
	md      metadata
	options handler.Options
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
		h.cipher, err = ss.ShadowCipher(method, password, h.md.key)
		if err != nil {
			return
		}
	}

	h.router = h.options.Router
	if h.router == nil {
		h.router = chain.NewRouter(chain.LoggerRouterOption(h.options.Logger))
	}

	return
}

func (h *ssuHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	start := time.Now()
	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return nil
	}

	pc, ok := conn.(net.PacketConn)
	if ok {
		if h.cipher != nil {
			pc = h.cipher.PacketConn(pc)
		}
		// standard UDP relay.
		pc = ss.UDPServerConn(pc, conn.RemoteAddr(), h.md.bufferSize)
	} else {
		if h.cipher != nil {
			conn = ss.ShadowConn(h.cipher.StreamConn(conn), nil)
		}
		// UDP over TCP
		pc = relay.UDPTunServerConn(conn)
	}

	// obtain a udp connection
	c, err := h.router.Dial(ctx, "udp", "") // UDP association
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

	t := time.Now()
	log.Infof("%s <-> %s", conn.LocalAddr(), cc.LocalAddr())
	h.relayPacket(pc, cc, log)
	log.WithFields(map[string]any{"duration": time.Since(t)}).
		Infof("%s >-< %s", conn.LocalAddr(), cc.LocalAddr())

	return nil
}

func (h *ssuHandler) relayPacket(pc1, pc2 net.PacketConn, log logger.Logger) (err error) {
	bufSize := h.md.bufferSize
	errc := make(chan error, 2)

	go func() {
		for {
			err := func() error {
				b := bufpool.Get(bufSize)
				defer bufpool.Put(b)

				n, addr, err := pc1.ReadFrom(*b)
				if err != nil {
					return err
				}

				if h.options.Bypass != nil && h.options.Bypass.Contains(context.Background(), addr.String()) {
					log.Warn("bypass: ", addr)
					return nil
				}

				if _, err = pc2.WriteTo((*b)[:n], addr); err != nil {
					return err
				}

				log.Tracef("%s >>> %s data: %d",
					pc2.LocalAddr(), addr, n)
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
				b := bufpool.Get(bufSize)
				defer bufpool.Put(b)

				n, raddr, err := pc2.ReadFrom(*b)
				if err != nil {
					return err
				}

				if h.options.Bypass != nil && h.options.Bypass.Contains(context.Background(), raddr.String()) {
					log.Warn("bypass: ", raddr)
					return nil
				}

				if _, err = pc1.WriteTo((*b)[:n], raddr); err != nil {
					return err
				}

				log.Tracef("%s <<< %s data: %d",
					pc2.LocalAddr(), raddr, n)
				return nil
			}()

			if err != nil {
				errc <- err
				return
			}
		}
	}()

	return <-errc
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
