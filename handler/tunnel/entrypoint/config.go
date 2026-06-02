package entrypoint

import (
	"net"
	"net/http"
	"time"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/sd"
)

// Config carries dependencies from the tunnel handler into the entrypoint.
//
// All fields must be set by the caller before calling New. The DialFunc
// bridges the package boundary to avoid an import cycle.
type Config struct {
	// Node is the local tunnel node ID (from tunnelHandler.id).
	Node string
	// Service is the parent handler's service name, used for ingress lookups,
	// logging, and TLS certificate selection.
	Service             string
	Ingress             ingress.Ingress
	SD                  sd.SD
	Logger              logger.Logger
	Recorder            recorder.RecorderObject
	SniffingWebsocket   bool
	WebsocketSampleRate float64
	// ReadTimeout is applied as SetReadDeadline on upstream connections
	// before sniffing HTTP/TLS reads. Also used as
	// http.Transport.ResponseHeaderTimeout. 0 or negative defaults to 15s.
	ReadTimeout time.Duration
	// ProxyProtocol is the PROXY protocol version (1 or 2) for the listener.
	ProxyProtocol int
	// KeepAlive enables HTTP keep-alive for the transport. Disabled by default.
	KeepAlive bool
	// Compression enables HTTP transport-level compression. Disabled by default.
	Compression bool
}

// DialFunc is the function signature for establishing a tunnel connection.
// Implemented by the parent package (tunnel) to avoid import cycles.
//
// ctx carries recorder objects and loggers for the tunnel connection.
// network is always "tcp" for entrypoint connections.
// tid is the string representation of the target tunnel ID.
type DialFunc func(ctx DialContext, network, tid string) (conn net.Conn, node, cid string, err error)

// DialContext carries metadata for a dial request.
// This interface satisfies the context.Context Value() contract,
// allowing the parent package to pass a real context.Context which is
// recovered via type assertion in the DialFunc implementation.
type DialContext interface {
	Value(any) any
}

// New creates a new Entrypoint with the given config and dial function.
//
// The config fields are copied into the Entrypoint struct. The dial function
// is stored as-is — nil functions cause dial failures at runtime, not at
// construction time.
//
// The HTTP transport is initialized immediately with ep.dial as its
// DialContext; responses time out after cfg.ReadTimeout (default 15s).
func New(cfg *Config, dialFn DialFunc) *Entrypoint {
	ep := &Entrypoint{
		node:                cfg.Node,
		service:             cfg.Service,
		ingress:             cfg.Ingress,
		sd:                  cfg.SD,
		log:                 cfg.Logger,
		recorder:            cfg.Recorder,
		sniffingWebsocket:   cfg.SniffingWebsocket,
		websocketSampleRate: cfg.WebsocketSampleRate,
		readTimeout:         cfg.ReadTimeout,
		dialFn:              dialFn,
	}
	ep.transport = &http.Transport{
		DialContext:           ep.dial,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: cfg.ReadTimeout,
		DisableKeepAlives:     !cfg.KeepAlive,
		DisableCompression:    !cfg.Compression,
	}
	return ep
}