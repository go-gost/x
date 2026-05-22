// Package wrapper provides net.Listener and net.Conn wrappers that
// enforce admission control at the network level.
//
// The listener wrapper checks each accepted connection against the
// admission controller before returning it to the caller. Denied
// connections are closed immediately and the listener continues
// accepting (transparent rejection).
//
// The connection wrappers (TCP, UDP, generic packet) check admission
// on each read operation, effectively dropping traffic from denied
// addresses without closing the underlying transport.
package wrapper

import (
	"context"
	"net"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/logger"
	xctx "github.com/go-gost/x/ctx"
)

// listener wraps a net.Listener and performs admission checks on each
// accepted connection. Connections from denied addresses are silently
// closed and the accept loop continues.
type listener struct {
	service   string
	net.Listener
	admission admission.Admission
	log       logger.Logger
}

// WrapListener wraps a net.Listener with admission control. If admission
// is nil, the original listener is returned unchanged (no-op).
//
// The service name is passed to the admission controller via
// admission.WithService so that the controller can distinguish
// between different services sharing the same admission rules.
func WrapListener(service string, admission admission.Admission, ln net.Listener) net.Listener {
	if admission == nil {
		return ln
	}
	return &listener{
		service:   service,
		Listener:  ln,
		admission: admission,
	}
}

// Accept blocks until a connection is accepted from the underlying
// listener, then checks it against the admission controller. Denied
// connections are closed and the loop retries. The caller never sees
// a rejected connection.
//
// The client address used for the admission check is determined by:
//  1. The srcAddr value from the connection's context (if available),
//     which is the original client address before any proxy protocol
//     or NAT rewriting.
//  2. Falling back to the raw RemoteAddr of the accepted connection.
func (ln *listener) Accept() (net.Conn, error) {
	for {
		c, err := ln.Listener.Accept()
		if err != nil {
			return nil, err
		}

		// Extract the context from the connection if it carries one.
		ctx := context.Background()
		if cc, ok := c.(xctx.Context); ok {
			if cv := cc.Context(); cv != nil {
				ctx = cv
			}
		}

		// Prefer the original source address from context (e.g. set by
		// proxy protocol handling), falling back to the raw remote address.
		clientAddr := c.RemoteAddr()
		if addr := xctx.SrcAddrFromContext(ctx); addr != nil {
			clientAddr = addr
		}

		if ln.admission != nil &&
			!ln.admission.Admit(ctx, clientAddr.Network(), clientAddr.String(), admission.WithService(ln.service)) {
			c.Close()
			continue
		}
		return c, err
	}
}
