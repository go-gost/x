// Package wrapper adapts a named quota onto a listener and its connections,
// resolving the quota.Limiter by name from the registry on every call so
// create/update/delete takes effect live and several services can share one.
package wrapper

import (
	"net"
	"sync"

	"github.com/go-gost/core/listener"
	"github.com/go-gost/x/registry"
)

type quotaListener struct {
	listener.Listener
	name string
	done chan struct{}
	once sync.Once
}

func WrapListener(ln listener.Listener, name string) listener.Listener {
	if ln == nil || name == "" {
		return ln
	}
	return &quotaListener{Listener: ln, name: name, done: make(chan struct{})}
}

func (ln *quotaListener) Accept() (net.Conn, error) {
	for {
		lim := registry.QuotaLimiterRegistry().Get(ln.name)
		if lim == nil {
			break
		}
		ch := lim.WaitChan() // before Blocked, to avoid a missed wakeup
		if !lim.Blocked() {
			break
		}
		// Park (not error) so the service's accept loop survives; ln.done wakes
		// it on listener close.
		select {
		case <-ch:
		case <-ln.done:
			return nil, net.ErrClosed
		}
	}

	c, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return WrapConn(c, ln.name), nil
}

func (ln *quotaListener) Close() error {
	// Wake a parked Accept, but do not close the (possibly shared) limiter.
	ln.once.Do(func() { close(ln.done) })
	return ln.Listener.Close()
}
