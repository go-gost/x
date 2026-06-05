// Package serial implements a handler for serial port connections in GOST.
//
// The serial handler operates in two distinct modes:
//
// # Mode 1 — Hop-based forwarding (h.hop != nil)
//
// When a hop is configured (typically via the -F CLI flag for forward
// proxies), the handler selects a target node from the hop and forwards
// traffic through that target's serial port. The forwarding path is:
//
//  1. Parse serial port parameters (baud rate, parity, etc.) from the local
//     connection address (e.g. "COM1,9600,even").
//  2. Override the port NAME with the target node's address — the target
//     specifies WHICH serial device to use, while the local address
//     specifies HOW to configure it.
//  3. Attempt to dial through the router's chain using network "serial".
//     If a chain IS configured, it handles the actual transport (e.g.
//     TCP/TLS/WS to a remote host, then a serial connector at the far end).
//  4. If the router has NO chain (or no router at all), fall back to
//     opening the serial port directly on the local machine.
//  5. Bidirectional data pipe between the client connection and the serial
//     port.
//
// # Mode 2 — Direct proxy (h.hop == nil)
//
// Without a hop, the handler acts as a simple pass-through: it dials the
// router with the sentinel address "@" (meaning "local"), then pipes data
// between the client connection and the router connection.
//
// # Traffic recording
//
// Raw traffic is recorded per-packet via recorderConn. Each successful
// Read/Write is logged with optional direction markers, timestamps, and
// hex dumps (controlled by RecorderOptions).
package serial

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	serial "github.com/go-gost/x/internal/util/serial"
	xrecorder "github.com/go-gost/x/recorder"
	"github.com/go-gost/x/registry"
)

func init() {
	registry.HandlerRegistry().Register("serial", NewHandler)
}

// serialHandler handles serial port connections. It can operate as a
// forwarder (with a hop) or as a simple pass-through proxy (without a hop).
type serialHandler struct {
	// hop selects a target node for forwarding mode. Set via Forward().
	hop hop.Hop
	// md holds parsed metadata (timeout).
	md metadata
	// options carries the standard handler options (router, logger, bypass, etc.).
	options handler.Options
	// recorder is the traffic recorder for serial handler traffic. It is selected
	// during Init() by matching the RecorderServiceHandlerSerial record name.
	recorder recorder.RecorderObject
}

// NewHandler creates a new serial handler with the given options.
// The handler must be initialized via Init() before use.
func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &serialHandler{
		options: options,
	}
}

// Init initializes the handler by parsing metadata and locating the
// traffic recorder for serial handler events. It implements handler.Initable.
func (h *serialHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}

	// Find the recorder whose Record name matches the serial handler
	// constant. Only one recorder per handler type is supported.
	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandlerSerial {
			h.recorder = ro
			break
		}
	}

	return
}

// Forward sets the hop used for forwarding mode. When a hop is configured,
// Handle() will select a target node and forward traffic through it.
// Implements handler.Forwarder.
func (h *serialHandler) Forward(hop hop.Hop) {
	h.hop = hop
}

// Handle processes an incoming serial port connection.
//
// The method always closes the connection on return (via defer). It follows
// one of two code paths depending on whether a hop has been configured:
//
//	Hop configured    → forwardSerial() — route through chain or open
//	                    serial port directly.
//	No hop            → Router.Dial("tcp", "@") — dial through router
//	                    chain to a local handler, then pipe data.
//
// The connection is wrapped in a recorderConn before any I/O, so all
// traffic through the handler is logged (subject to recorder config).
func (h *serialHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	log := h.options.Logger

	log = log.WithFields(map[string]any{
		"network": "serial",
		"remote":  conn.RemoteAddr().String(),
		"local":   conn.LocalAddr().String(),
		"sid":     xctx.SidFromContext(ctx).String(),
	})

	// Wrap the connection for per-packet traffic recording. The recorderConn
	// delegates Read/Write to the underlying connection, recording each
	// successful transfer. When no recorder is configured, the wrapper is
	// effectively a no-op (the nil checks on each call are cheap).
	conn = &recorderConn{
		Conn:     conn,
		recorder: h.recorder,
	}

	// --- Mode 1: Hop-based forwarding ---
	// Select a target node from the hop and forward serial traffic to it.
	if h.hop != nil {
		target := h.hop.Select(ctx)
		if target == nil {
			err := errors.New("target not available")
			log.Error(err)
			return err
		}
		log = log.WithFields(map[string]any{
			"node": target.Name,
			"dst":  target.Addr,
		})
		return h.forwardSerial(ctx, conn, target, log)
	}

	// --- Mode 2: Direct proxy (no hop) ---
	// Dial through the router chain with the sentinel address "@" (meaning
	// "local" or "loopback"). The router's chain is expected to route "@"
	// to an appropriate handler (e.g. a local relay listener).
	if h.options.Router == nil {
		err := errors.New("router not available")
		log.Error(err)
		return err
	}
	cc, err := h.options.Router.Dial(ctx, "tcp", "@")
	if err != nil {
		log.Error(err)
		return err
	}
	defer cc.Close()

	t := time.Now()
	log.Infof("%s <-> %s", conn.LocalAddr(), "@")
	// xnet.Transport(conn, cc)
	if err := xnet.Pipe(ctx, conn, cc); err != nil {
		log.Errorf("pipe: %v", err)
		return err
	}
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.LocalAddr(), "@")

	return nil
}

// forwardSerial forwards traffic from conn to the target node's serial port.
//
// The method implements a two-tier dialing strategy:
//
//  1. Router chain (preferred): If a router with a chain is configured,
//     dial through the chain with network "serial". The chain handles
//     transport (TCP/TLS/WS/etc.) and uses a serial connector at the
//     far end to reach the remote serial device.
//
//  2. Direct open (fallback): If no router chain exists or the chain
//     returned no connection without error, open the serial port
//     directly on the local machine. This is the typical case when
//     GOST runs on the same host as the serial device.
//
// Serial port parameters (baud rate, parity, stop bits) are parsed from
// the local connection address, while the port NAME comes from the
// target node's address. This separation allows the hop target to
// specify WHICH device to use while the local port configuration
// specifies HOW to talk to it.
func (h *serialHandler) forwardSerial(ctx context.Context, conn net.Conn, target *chain.Node, log logger.Logger) (err error) {
	log.Debugf("%s >> %s", conn.LocalAddr(), target.Addr)
	var port io.ReadWriteCloser

	// Parse serial configuration from the local connection address.
	// The address format is: "NAME,BAUD,PARITY" (e.g. "COM1,9600,even").
	// Baud and parity default to 9600 and None if not specified.
	cfg := serial.ParseConfigFromAddr(conn.LocalAddr().String())
	// Override the port name with the target node's address — the hop
	// target determines WHICH serial device to open.
	cfg.Name = target.Addr

	// Tier 1: Try routing through the chain (if configured).
	// The chain dials with network="serial", which selects a transport
	// whose connector understands serial addresses. This path supports
	// remote serial port access through GOST's proxy chain.
	if h.options.Router != nil {
		if opts := h.options.Router.Options(); opts != nil && opts.Chain != nil {
			port, err = h.options.Router.Dial(ctx, "serial", serial.AddrFromConfig(cfg))
		}
	}
	// Tier 2: Fall back to directly opening the local serial port.
	// This runs when:
	//   - No router is configured, OR
	//   - The router has no chain, OR
	//   - The router chain returned (nil, nil) — meaning no route was
	//     available but no error occurred either.
	// If the router chain returned an actual error, we skip the fallback
	// and propagate the error — a configured chain is authoritative.
	if port == nil && err == nil {
		if h.options.Router != nil {
			if opts := h.options.Router.Options(); opts != nil && opts.Chain != nil {
				log.Warnf("chain dial returned no connection and no error, falling back to direct serial port")
			}
		}
		cfg.ReadTimeout = h.md.timeout
		port, err = serial.OpenPort(cfg)
	}
	if err != nil {
		log.Error(err)
		return err
	}
	defer port.Close()

	t := time.Now()
	log.Infof("%s <-> %s", conn.LocalAddr(), target.Addr)
	// xnet.Transport(conn, port)
	// Pipe bidirectionally between the client connection and the serial port.
	// xnet.Pipe spawns two goroutines and returns on first error or when
	// both directions complete.
	if err := xnet.Pipe(ctx, conn, port); err != nil {
		log.Errorf("pipe: %v", err)
		return err
	}
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Infof("%s >-< %s", conn.LocalAddr(), target.Addr)

	return nil
}
