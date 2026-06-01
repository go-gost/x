package tunnel

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/service"
	xnet "github.com/go-gost/x/internal/net"
	xrecorder "github.com/go-gost/x/recorder"
	xservice "github.com/go-gost/x/service"
)

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

func (h *tunnelHandler) createEntrypointService(addr string, ingress ingress.Ingress) (service.Service, error) {
	ep := &entrypoint{
		node:    h.id,
		service: h.options.Service,
		pool:    h.pool,
		ingress: ingress,
		sd:      h.md.sd,
		log: h.log.WithFields(map[string]any{
			"kind": "entrypoint",
		}),
		sniffingWebsocket:   h.md.sniffingWebsocket,
		websocketSampleRate: h.md.sniffingWebsocketSampleRate,
		readTimeout:         h.md.entryPointReadTimeout,
	}
	ep.transport = &http.Transport{
		DialContext:           ep.dial,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: h.md.entryPointReadTimeout,
		DisableKeepAlives:     !h.md.entryPointKeepalive,
		DisableCompression:    !h.md.entryPointCompression,
	}

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandler {
			ep.recorder = ro
			break
		}
	}

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
	epListener := newTCPListener(ln,
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
	epHandler := &entrypointHandler{
		ep: ep,
	}
	if err = epHandler.Init(nil); err != nil {
		return nil, err
	}

	return xservice.NewService(
		serviceName, epListener, epHandler,
		xservice.LoggerOption(log),
	), nil
}