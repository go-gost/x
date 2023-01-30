package remote

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/forward"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("rtcp", NewHandler)
	registry.HandlerRegistry().Register("rudp", NewHandler)
}

type forwardHandler struct {
	hop     chain.Hop
	router  *chain.Router
	md      metadata
	options handler.Options
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &forwardHandler{
		options: options,
	}
}

func (h *forwardHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}

	h.router = h.options.Router
	if h.router == nil {
		h.router = chain.NewRouter(chain.LoggerRouterOption(h.options.Logger))
	}

	return
}

// Forward implements handler.Forwarder.
func (h *forwardHandler) Forward(hop chain.Hop) {
	h.hop = hop
}

func (h *forwardHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
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

	network := "tcp"
	if _, ok := conn.(net.PacketConn); ok {
		network = "udp"
	}

	var rw io.ReadWriter = conn
	var host string
	var protocol string
	if h.md.sniffing {
		if network == "tcp" {
			rw, host, protocol, _ = forward.Sniffing(ctx, conn)
		}
	}

	if protocol == forward.ProtoHTTP {
		h.handleHTTP(ctx, rw, log)
		return nil
	}

	var target *chain.Node
	if h.hop != nil {
		target = h.hop.Select(ctx,
			chain.HostSelectOption(host),
			chain.ProtocolSelectOption(protocol),
		)
	}
	if target == nil {
		err := errors.New("target not available")
		log.Error(err)
		return err
	}

	log = log.WithFields(map[string]any{
		"dst": fmt.Sprintf("%s/%s", target.Addr, network),
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), target.Addr)

	cc, err := h.router.Dial(ctx, network, target.Addr)
	if err != nil {
		log.Error(err)
		// TODO: the router itself may be failed due to the failed node in the router,
		// the dead marker may be a wrong operation.
		if marker := target.Marker(); marker != nil {
			marker.Mark()
		}
		return err
	}
	defer cc.Close()
	if marker := target.Marker(); marker != nil {
		marker.Reset()
	}

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), target.Addr)
	xnet.Transport(rw, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), target.Addr)

	return nil
}

func (h *forwardHandler) handleHTTP(ctx context.Context, rw io.ReadWriter, log logger.Logger) (err error) {
	br := bufio.NewReader(rw)
	var connPool sync.Map

	resp := &http.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		StatusCode: http.StatusServiceUnavailable,
	}

	for {
		err = func() error {
			req, err := http.ReadRequest(br)
			if err != nil {
				return err
			}

			var target *chain.Node
			if h.hop != nil {
				target = h.hop.Select(ctx,
					chain.HostSelectOption(req.Host),
					chain.ProtocolSelectOption(forward.ProtoHTTP),
				)
			}
			if target == nil {
				return resp.Write(rw)
			}

			log = log.WithFields(map[string]any{
				"dst": target.Addr,
			})

			// log.Debugf("%s >> %s", conn.RemoteAddr(), target.Addr)

			var cc net.Conn
			if v, ok := connPool.Load(target); ok {
				cc = v.(net.Conn)
				log.Debugf("reuse connection to node %s(%s)", target.Name, target.Addr)
			}
			if cc == nil {
				cc, err = h.router.Dial(ctx, "tcp", target.Addr)
				if err != nil {
					// TODO: the router itself may be failed due to the failed node in the router,
					// the dead marker may be a wrong operation.
					if marker := target.Marker(); marker != nil {
						marker.Mark()
					}
					return resp.Write(rw)
				}
				if marker := target.Marker(); marker != nil {
					marker.Reset()
				}
				connPool.Store(target, cc)
				log.Debugf("new connection to node %s(%s)", target.Name, target.Addr)

				go func() {
					defer cc.Close()
					xnet.CopyBuffer(rw, cc, 8192)
					connPool.Delete(target)
				}()
			}

			if httpSettings := target.Options().HTTP; httpSettings != nil {
				if httpSettings.Host != "" {
					req.Host = httpSettings.Host
				}
				for k, v := range httpSettings.Header {
					req.Header.Set(k, v)
				}
			}

			if log.IsLevelEnabled(logger.TraceLevel) {
				dump, _ := httputil.DumpRequest(req, false)
				log.Trace(string(dump))
			}
			if err := req.Write(cc); err != nil {
				return resp.Write(rw)
			}

			if req.Header.Get("Upgrade") == "websocket" {
				err := xnet.CopyBuffer(cc, br, 8192)
				if err == nil {
					err = io.EOF
				}
				return err
			}

			return nil
		}()
		if err != nil {
			break
		}
	}

	connPool.Range(func(key, value any) bool {
		if value != nil {
			value.(net.Conn).Close()
		}
		return true
	})

	return
}

func (h *forwardHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}
