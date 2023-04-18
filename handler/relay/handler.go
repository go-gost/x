package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/listener"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/service"
	"github.com/go-gost/relay"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/registry"
	xservice "github.com/go-gost/x/service"
)

var (
	ErrBadVersion   = errors.New("relay: bad version")
	ErrUnknownCmd   = errors.New("relay: unknown command")
	ErrUnauthorized = errors.New("relay: unauthorized")
	ErrRateLimit    = errors.New("relay: rate limiting exceeded")
)

func init() {
	registry.HandlerRegistry().Register("relay", NewHandler)
}

type relayHandler struct {
	hop     chain.Hop
	router  *chain.Router
	md      metadata
	options handler.Options
	ep      service.Service
	pool    *ConnectorPool
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &relayHandler{
		options: options,
		pool:    NewConnectorPool(),
	}
}

func (h *relayHandler) Init(md md.Metadata) (err error) {
	if err := h.parseMetadata(md); err != nil {
		return err
	}

	h.router = h.options.Router
	if h.router == nil {
		h.router = chain.NewRouter(chain.LoggerRouterOption(h.options.Logger))
	}

	if err = h.initEntryPoint(); err != nil {
		return
	}
	return nil
}

func (h *relayHandler) initEntryPoint() (err error) {
	if h.md.entryPoint == "" {
		return
	}

	network := "tcp"
	if xnet.IsIPv4(h.md.entryPoint) {
		network = "tcp4"
	}

	ln, err := net.Listen(network, h.md.entryPoint)
	if err != nil {
		h.options.Logger.Error(err)
		return
	}

	serviceName := fmt.Sprintf("%s-ep-%s", h.options.Service, ln.Addr())
	log := h.options.Logger.WithFields(map[string]any{
		"service":  serviceName,
		"listener": "tcp",
		"handler":  "ep-tunnel",
		"kind":     "service",
	})
	epListener := newTCPListener(ln,
		listener.AddrOption(h.md.entryPoint),
		listener.ServiceOption(serviceName),
		listener.LoggerOption(log.WithFields(map[string]any{
			"kind": "listener",
		})),
	)
	if err = epListener.Init(nil); err != nil {
		return
	}
	epHandler := newTunnelHandler(
		h.pool,
		h.md.ingress,
		handler.ServiceOption(serviceName),
		handler.LoggerOption(log.WithFields(map[string]any{
			"kind": "handler",
		})),
	)
	if err = epHandler.Init(nil); err != nil {
		return
	}

	h.ep = xservice.NewService(
		serviceName, epListener, epHandler,
		xservice.LoggerOption(log),
	)
	go h.ep.Serve()
	log.Infof("entrypoint: %s", h.ep.Addr())

	return
}

// Forward implements handler.Forwarder.
func (h *relayHandler) Forward(hop chain.Hop) {
	h.hop = hop
}

func (h *relayHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	start := time.Now()
	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())

	defer func() {
		if err != nil {
			conn.Close()
		}
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return ErrRateLimit
	}

	if h.md.readTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(h.md.readTimeout))
	}

	req := relay.Request{}
	if _, err := req.ReadFrom(conn); err != nil {
		return err
	}

	conn.SetReadDeadline(time.Time{})

	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	if req.Version != relay.Version1 {
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		return ErrBadVersion
	}

	var user, pass string
	var address string
	var tunnelID relay.TunnelID
	for _, f := range req.Features {
		switch f.Type() {
		case relay.FeatureUserAuth:
			if feature, _ := f.(*relay.UserAuthFeature); feature != nil {
				user, pass = feature.Username, feature.Password
			}
		case relay.FeatureAddr:
			if feature, _ := f.(*relay.AddrFeature); feature != nil {
				address = net.JoinHostPort(feature.Host, strconv.Itoa(int(feature.Port)))
			}
		case relay.FeatureTunnel:
			if feature, _ := f.(*relay.TunnelFeature); feature != nil {
				tunnelID = relay.NewTunnelID(feature.ID[:])
			}
		}
	}

	if user != "" {
		log = log.WithFields(map[string]any{"user": user})
	}

	if h.options.Auther != nil &&
		!h.options.Auther.Authenticate(ctx, user, pass) {
		resp.Status = relay.StatusUnauthorized
		resp.WriteTo(conn)
		return ErrUnauthorized
	}

	network := "tcp"
	if (req.Cmd & relay.FUDP) == relay.FUDP {
		network = "udp"
	}

	if h.hop != nil {
		defer conn.Close()
		// forward mode
		return h.handleForward(ctx, conn, network, log)
	}

	switch req.Cmd & relay.CmdMask {
	case 0, relay.CmdConnect:
		defer conn.Close()

		if !tunnelID.IsZero() {
			return h.handleConnectTunnel(ctx, conn, network, address, tunnelID, log)
		}
		return h.handleConnect(ctx, conn, network, address, log)
	case relay.CmdBind:
		if !tunnelID.IsZero() {
			return h.handleBindTunnel(ctx, conn, network, tunnelID, log)
		}

		defer conn.Close()
		return h.handleBind(ctx, conn, network, address, log)
	default:
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		return ErrUnknownCmd
	}
}

// Close implements io.Closer interface.
func (h *relayHandler) Close() error {
	if h.ep != nil {
		return h.ep.Close()
	}
	return nil
}

func (h *relayHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}
