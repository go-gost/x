package local

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/config"
	ctxvalue "github.com/go-gost/x/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/forward"
	tls_util "github.com/go-gost/x/internal/util/tls"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("tcp", NewHandler)
	registry.HandlerRegistry().Register("udp", NewHandler)
	registry.HandlerRegistry().Register("forward", NewHandler)
}

type forwardHandler struct {
	hop     hop.Hop
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
func (h *forwardHandler) Forward(hop hop.Hop) {
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
	if network == "tcp" && h.md.sniffing {
		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Now().Add(h.md.sniffingTimeout))
		}
		rw, host, protocol, _ = forward.Sniffing(ctx, conn)
		log.Debugf("sniffing: host=%s, protocol=%s", host, protocol)
		if h.md.sniffingTimeout > 0 {
			conn.SetReadDeadline(time.Time{})
		}
	}

	if protocol == forward.ProtoHTTP {
		h.handleHTTP(ctx, rw, conn.RemoteAddr(), log)
		return nil
	}

	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "0")
	}

	var target *chain.Node
	if host != "" {
		target = &chain.Node{
			Addr: host,
		}
	}
	if h.hop != nil {
		target = h.hop.Select(ctx,
			hop.HostSelectOption(host),
			hop.ProtocolSelectOption(protocol),
		)
	}
	if target == nil {
		err := errors.New("target not available")
		log.Error(err)
		return err
	}

	addr := target.Addr
	if opts := target.Options(); opts != nil {
		switch opts.Network {
		case "unix":
			network = opts.Network
		default:
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr += ":0"
			}
		}
	}

	log = log.WithFields(map[string]any{
		"host": host,
		"node": target.Name,
		"dst":  fmt.Sprintf("%s/%s", addr, network),
	})

	log.Debugf("%s >> %s", conn.RemoteAddr(), addr)

	cc, err := h.router.Dial(ctx, network, addr)
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
	log.Infof("%s <-> %s", conn.RemoteAddr(), target.Addr)
	xnet.Transport(rw, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.RemoteAddr(), target.Addr)

	return nil
}

func (h *forwardHandler) handleHTTP(ctx context.Context, rw io.ReadWriter, remoteAddr net.Addr, log logger.Logger) (err error) {
	br := bufio.NewReader(rw)

	var cc net.Conn
	for {
		resp := &http.Response{
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
			StatusCode: http.StatusServiceUnavailable,
		}

		err = func() error {
			req, err := http.ReadRequest(br)
			if err != nil {
				// log.Errorf("read http request: %v", err)
				return err
			}

			if log.IsLevelEnabled(logger.TraceLevel) {
				dump, _ := httputil.DumpRequest(req, false)
				log.Trace(string(dump))
			}

			host := req.Host
			if _, _, err := net.SplitHostPort(host); err != nil {
				host = net.JoinHostPort(host, "80")
			}
			if bp := h.options.Bypass; bp != nil && bp.Contains(ctx, "tcp", host, bypass.WithPathOption(req.RequestURI)) {
				log.Debugf("bypass: %s %s", host, req.RequestURI)
				resp.StatusCode = http.StatusForbidden
				return resp.Write(rw)
			}

			if addr := getRealClientAddr(req, remoteAddr); addr != remoteAddr {
				log = log.WithFields(map[string]any{
					"src": addr.String(),
				})
				remoteAddr = addr
				ctx = ctxvalue.ContextWithClientAddr(ctx, ctxvalue.ClientAddr(remoteAddr.String()))
			}

			target := &chain.Node{
				Addr: req.Host,
			}
			if h.hop != nil {
				target = h.hop.Select(ctx,
					hop.HostSelectOption(req.Host),
					hop.ProtocolSelectOption(forward.ProtoHTTP),
					hop.PathSelectOption(req.URL.Path),
				)
			}
			if target == nil {
				log.Warnf("node for %s not found", req.Host)
				resp.StatusCode = http.StatusBadGateway
				return resp.Write(rw)
			}

			log = log.WithFields(map[string]any{
				"host": req.Host,
				"node": target.Name,
				"dst":  target.Addr,
			})
			log.Debugf("find node for host %s -> %s(%s)", req.Host, target.Name, target.Addr)

			if httpSettings := target.Options().HTTP; httpSettings != nil {
				if auther := httpSettings.Auther; auther != nil {
					username, password, _ := req.BasicAuth()
					id, ok := auther.Authenticate(ctx, username, password)
					if !ok {
						resp.StatusCode = http.StatusUnauthorized
						resp.Header.Set("WWW-Authenticate", "Basic")
						log.Warnf("node %s(%s) 401 unauthorized", target.Name, target.Addr)
						return resp.Write(rw)
					}
					ctx = ctxvalue.ContextWithClientID(ctx, ctxvalue.ClientID(id))
				}

				if httpSettings.Host != "" {
					req.Host = httpSettings.Host
				}
				for k, v := range httpSettings.Header {
					req.Header.Set(k, v)
				}

				for _, re := range httpSettings.Rewrite {
					if re.Pattern.MatchString(req.URL.Path) {
						if s := re.Pattern.ReplaceAllString(req.URL.Path, re.Replacement); s != "" {
							req.URL.Path = s
							break
						}
					}
				}
			}

			cc, err = h.router.Dial(ctx, "tcp", target.Addr)
			if err != nil {
				// TODO: the router itself may be failed due to the failed node in the router,
				// the dead marker may be a wrong operation.
				if marker := target.Marker(); marker != nil {
					marker.Mark()
				}
				log.Warnf("connect to node %s(%s) failed: %v", target.Name, target.Addr, err)
				return resp.Write(rw)
			}
			if marker := target.Marker(); marker != nil {
				marker.Reset()
			}

			log.Debugf("connection to node %s(%s)", target.Name, target.Addr)

			if tlsSettings := target.Options().TLS; tlsSettings != nil {
				cfg := &tls.Config{
					ServerName:         tlsSettings.ServerName,
					InsecureSkipVerify: !tlsSettings.Secure,
				}
				tls_util.SetTLSOptions(cfg, &config.TLSOptions{
					MinVersion:   tlsSettings.Options.MinVersion,
					MaxVersion:   tlsSettings.Options.MaxVersion,
					CipherSuites: tlsSettings.Options.CipherSuites,
				})
				cc = tls.Client(cc, cfg)
			}

			if err := req.Write(cc); err != nil {
				cc.Close()
				log.Warnf("send request to node %s(%s): %v", target.Name, target.Addr, err)
				return resp.Write(rw)
			}

			if req.Header.Get("Upgrade") == "websocket" {
				err := xnet.Transport(cc, xio.NewReadWriter(br, rw))
				if err == nil {
					err = io.EOF
				}
				return err
			}

			go func() {
				defer cc.Close()

				res, err := http.ReadResponse(bufio.NewReader(cc), req)
				if err != nil {
					log.Warnf("read response from node %s(%s): %v", target.Name, target.Addr, err)
					resp.Write(rw)
					return
				}

				if log.IsLevelEnabled(logger.TraceLevel) {
					dump, _ := httputil.DumpResponse(res, false)
					log.Trace(string(dump))
				}

				if err = res.Write(rw); err != nil {
					log.Errorf("write response from node %s(%s): %v", target.Name, target.Addr, err)
				}
			}()

			return nil
		}()

		if err != nil {
			if cc != nil {
				cc.Close()
			}
			break
		}
	}

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

func getRealClientAddr(req *http.Request, raddr net.Addr) net.Addr {
	if req == nil {
		return nil
	}
	// cloudflare CDN
	sip := req.Header.Get("CF-Connecting-IP")
	if sip == "" {
		ss := strings.Split(req.Header.Get("X-Forwarded-For"), ",")
		if len(ss) > 0 && ss[0] != "" {
			sip = ss[0]
		}
	}
	if sip == "" {
		sip = req.Header.Get("X-Real-Ip")
	}

	ip := net.ParseIP(sip)
	if ip == nil {
		return raddr
	}

	_, sp, _ := net.SplitHostPort(raddr.String())

	port, _ := strconv.Atoi(sp)

	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
}
