package sniffing

import (
	"context"
	"net"
	"sync"
)

// HandleFunc handles a connection whose protocol has been detected as proto.
// The receiver s carries the per-connection Sniffer state (MITM certificate,
// HTTP cache, recorder, etc.).
type HandleFunc func(s *Sniffer, ctx context.Context, network string, conn net.Conn, opts ...HandleOption) error

var protoHandlers sync.Map // map[string]HandleFunc

// Register associates a protocol with its handler. Duplicate registration
// panics, mirroring the house registry pattern.
func Register(proto string, fn HandleFunc) {
	if _, dup := protoHandlers.LoadOrStore(proto, fn); dup {
		panic("sniffing: duplicate protocol handler: " + proto)
	}
}

// Get returns the handler registered for proto.
func Get(proto string) (HandleFunc, bool) {
	v, ok := protoHandlers.Load(proto)
	if !ok {
		return nil, false
	}
	return v.(HandleFunc), true
}

// Dispatch routes a detected protocol to its registered handler. It returns
// (false, nil) when no handler is registered for proto, signalling the caller
// to fall through to raw forwarding.
func Dispatch(s *Sniffer, ctx context.Context, network string, conn net.Conn, proto string, opts ...HandleOption) (handled bool, err error) {
	fn, ok := Get(proto)
	if !ok {
		return false, nil
	}
	return true, fn(s, ctx, network, conn, opts...)
}

func init() {
	Register(ProtoHTTP, (*Sniffer).HandleHTTP)
	Register(ProtoTLS, (*Sniffer).HandleTLS)
	Register(ProtoRedis, (*Sniffer).HandleRedis)
}
