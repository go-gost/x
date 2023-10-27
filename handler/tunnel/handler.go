package tunnel

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
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/service"
	"github.com/go-gost/relay"
	xnet "github.com/go-gost/x/internal/net"
	auth_util "github.com/go-gost/x/internal/util/auth"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
	xservice "github.com/go-gost/x/service"
)

var (
	ErrBadVersion   = errors.New("relay: bad version")
	ErrUnknownCmd   = errors.New("relay: unknown command")
	ErrTunnelID     = errors.New("tunnel: invalid tunnel ID")
	ErrUnauthorized = errors.New("relay: unauthorized")
	ErrRateLimit    = errors.New("relay: rate limiting exceeded")
)

func init() {
	registry.HandlerRegistry().Register("tunnel", NewHandler)
}

type tunnelHandler struct {
	router   *chain.Router
	md       metadata
	options  handler.Options
	pool     *ConnectorPool
	recorder recorder.RecorderObject
	epSvc    service.Service
	ep       *entrypoint
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &tunnelHandler{
		options: options,
		pool:    NewConnectorPool(),
	}
}

func (h *tunnelHandler) Init(md md.Metadata) (err error) {
	if err := h.parseMetadata(md); err != nil {
		return err
	}

	h.router = h.options.Router
	if h.router == nil {
		h.router = chain.NewRouter(chain.LoggerRouterOption(h.options.Logger))
	}

	if opts := h.router.Options(); opts != nil {
		for _, ro := range opts.Recorders {
			if ro.Record == xrecorder.RecorderServiceHandlerTunnelEndpoint {
				h.recorder = ro
				break
			}
		}
	}

	h.ep = &entrypoint{
		pool:    h.pool,
		ingress: h.md.ingress,
		log: h.options.Logger.WithFields(map[string]any{
			"kind": "entrypoint",
		}),
	}
	if err = h.initEntrypoint(); err != nil {
		return
	}

	return nil
}

func (h *tunnelHandler) initEntrypoint() (err error) {
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
		"handler":  "tunnel-ep",
		"kind":     "service",
	})
	epListener := newTCPListener(ln,
		listener.AddrOption(h.md.entryPoint),
		listener.ServiceOption(serviceName),
		listener.ProxyProtocolOption(h.md.entryPointProxyProtocol),
		listener.LoggerOption(log.WithFields(map[string]any{
			"kind": "listener",
		})),
	)
	if err = epListener.Init(nil); err != nil {
		return
	}
	epHandler := &entrypointHandler{
		ep: h.ep,
	}
	if err = epHandler.Init(nil); err != nil {
		return
	}

	h.epSvc = xservice.NewService(
		serviceName, epListener, epHandler,
		xservice.LoggerOption(log),
	)
	go h.epSvc.Serve()
	log.Infof("entrypoint: %s", h.epSvc.Addr())

	return
}

func (h *tunnelHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
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

	ctx = auth_util.ContextWithClientAddr(ctx, auth_util.ClientAddr(conn.RemoteAddr().String()))

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
	var srcAddr, dstAddr string
	var networkID relay.NetworkID
	var tunnelID relay.TunnelID
	for _, f := range req.Features {
		switch f.Type() {
		case relay.FeatureUserAuth:
			if feature, _ := f.(*relay.UserAuthFeature); feature != nil {
				user, pass = feature.Username, feature.Password
			}
		case relay.FeatureAddr:
			if feature, _ := f.(*relay.AddrFeature); feature != nil {
				v := net.JoinHostPort(feature.Host, strconv.Itoa(int(feature.Port)))
				if srcAddr != "" {
					dstAddr = v
				} else {
					srcAddr = v
				}
			}
		case relay.FeatureTunnel:
			if feature, _ := f.(*relay.TunnelFeature); feature != nil {
				tunnelID = relay.NewTunnelID(feature.ID[:])
			}
		case relay.FeatureNetwork:
			if feature, _ := f.(*relay.NetworkFeature); feature != nil {
				networkID = feature.Network
			}
		}
	}

	if tunnelID.IsZero() {
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		return ErrTunnelID
	}

	if user != "" {
		log = log.WithFields(map[string]any{"user": user})
	}

	if h.options.Auther != nil {
		id, ok := h.options.Auther.Authenticate(ctx, user, pass)
		if !ok {
			resp.Status = relay.StatusUnauthorized
			resp.WriteTo(conn)
			return ErrUnauthorized
		}
		ctx = auth_util.ContextWithID(ctx, auth_util.ID(id))
	}

	network := networkID.String()
	if (req.Cmd & relay.FUDP) == relay.FUDP {
		network = "udp"
	}

	switch req.Cmd & relay.CmdMask {
	case relay.CmdConnect:
		defer conn.Close()

		log.Debugf("connect: %s >> %s/%s", srcAddr, dstAddr, network)
		return h.handleConnect(ctx, conn, network, srcAddr, dstAddr, tunnelID, log)
	case relay.CmdBind:
		log.Debugf("bind: %s >> %s/%s", srcAddr, dstAddr, network)
		return h.handleBind(ctx, conn, network, dstAddr, tunnelID, log)
	default:
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		return ErrUnknownCmd
	}
}

// Close implements io.Closer interface.
func (h *tunnelHandler) Close() error {
	return nil
}

func (h *tunnelHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}
