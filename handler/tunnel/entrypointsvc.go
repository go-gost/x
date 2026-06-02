package tunnel

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/service"
	xnet "github.com/go-gost/x/internal/net"
	xrecorder "github.com/go-gost/x/recorder"
	xservice "github.com/go-gost/x/service"

	epkg "github.com/go-gost/x/handler/tunnel/entrypoint"
)

// initEntrypoints starts all configured entrypoint services.
//
// It starts the primary entrypoint (from the "entrypoint" metadata key) and
// any additional entrypoints (from the "entrypoints" metadata array). Each
// entrypoint is created via createEntrypointService and started in its own
// goroutine. Services are tracked in h.entrypoints for later cleanup in
// Close().
func (h *tunnelHandler) initEntrypoints() (err error) {
	if h.md.entryPoint != "" {
		svc, err := h.createEntrypointService(h.md.entryPoint, h.md.ingress)
		if err != nil {
			return err
		}
		go svc.Serve()

		h.entrypoints = append(h.entrypoints, svc)
		h.log.Infof("entrypoint: %s", svc.Addr())
	}

	for _, ep := range h.md.entrypoints {
		if ep.Addr == "" {
			continue
		}
		svc, err := h.createEntrypointService(ep.Addr, ep.Ingress)
		if err != nil {
			return err
		}
		go svc.Serve()

		h.entrypoints = append(h.entrypoints, svc)
		h.log.Infof("entrypoint: %s %s", ep.Name, svc.Addr())
	}

	return
}

// createEntrypointService creates a GOST service wrapping an entrypoint
// listener and handler for the given address and ingress rule table.
//
// It constructs:
//  1. A Dialer populated from the tunnel handler's state (node, pool, sd)
//     wrapped in a closure that implements epkg.DialFunc.
//  2. An epkg.Entrypoint via epkg.New() with all configured options.
//  3. A TCP listener via net.Listen and epkg.NewTCPListener.
//  4. An entrypoint handler via epkg.NewHandler.
//  5. A GOST service via xservice.NewService.
//
// The recorder object is selected from h.options.Recorders by matching
// RecorderServiceHandler record type.
func (h *tunnelHandler) createEntrypointService(addr string, ing ingress.Ingress) (service.Service, error) {
	var ro recorder.RecorderObject
	for _, r := range h.options.Recorders {
		if r.Record == xrecorder.RecorderServiceHandler {
			ro = r
			break
		}
	}

	dialFn := func(ctx epkg.DialContext, network, tid string) (net.Conn, string, string, error) {
		d := &Dialer{
			Node:    h.id,
			Pool:    h.pool,
			SD:      h.md.sd,
			Retry:   3,
			Timeout: 15 * time.Second,
			Log:     h.log,
		}
		return d.Dial(ctx.(context.Context), network, tid)
	}

	ep := epkg.New(&epkg.Config{
		Node:                h.id,
		Service:             h.options.Service,
		Ingress:             ing,
		SD:                  h.md.sd,
		Logger:              h.log.WithFields(map[string]any{"kind": "entrypoint"}),
		Recorder:            ro,
		SniffingWebsocket:   h.md.sniffingWebsocket,
		WebsocketSampleRate: h.md.sniffingWebsocketSampleRate,
		ReadTimeout:         h.md.entryPointReadTimeout,
		ProxyProtocol:       h.md.entryPointProxyProtocol,
		KeepAlive:           h.md.entryPointKeepalive,
		Compression:         h.md.entryPointCompression,
	}, dialFn)

	network := "tcp"
	if xnet.IsIPv4(addr) {
		network = "tcp4"
	}

	ln, err := net.Listen(network, addr)
	if err != nil {
		h.log.Error(err)
		return nil, err
	}

	serviceName := fmt.Sprintf("%s-ep-%s", h.options.Service, ln.Addr())
	log := h.log.WithFields(map[string]any{
		"service":  serviceName,
		"listener": "tcp",
		"handler":  "tunnel-ep",
		"kind":     "service",
	})

	epListener := epkg.NewTCPListener(ln,
		listener.AddrOption(addr),
		listener.ServiceOption(serviceName),
		listener.ProxyProtocolOption(h.md.entryPointProxyProtocol),
		listener.LoggerOption(log.WithFields(map[string]any{
			"kind": "listener",
		})),
	)
	if err = epListener.Init(nil); err != nil {
		return nil, err
	}

	epHandler := epkg.NewHandler(ep)
	if err = epHandler.Init(nil); err != nil {
		return nil, err
	}

	return xservice.NewService(
		serviceName, epListener, epHandler,
		xservice.LoggerOption(log),
	), nil
}