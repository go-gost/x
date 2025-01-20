package wrapper

import (
	"net"

	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/traffic"
	traffic_limiter "github.com/go-gost/x/limiter/traffic"
)

type listener struct {
	net.Listener
	limiter traffic.TrafficLimiter
	service string
}

func WrapListener(service string, ln net.Listener, limiter traffic.TrafficLimiter) net.Listener {
	if limiter == nil {
		return ln
	}

	return &listener{
		Listener: ln,
		limiter:  limiter,
		service:  service,
	}
}

func (ln *listener) Accept() (net.Conn, error) {
	c, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return WrapConn(c, ln.limiter, traffic_limiter.ServiceLimitKey,
		limiter.ScopeOption(limiter.ScopeService),
		limiter.ServiceOption(ln.service),
		limiter.NetworkOption(ln.Addr().Network()),
	), nil
}
