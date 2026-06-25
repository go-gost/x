package sni

import (
	"context"
	"errors"
	"net"
	"time"

	xctx "github.com/go-gost/x/ctx"
	xrecorder "github.com/go-gost/x/recorder"
)

var (
	errRouterNotAvailable = errors.New("sni: router not available")
)

// newRecorderObject creates a HandlerRecorderObject populated with connection
// metadata (service, addresses, network type, session ID, client address).
func (h *sniHandler) newRecorderObject(ctx context.Context, conn net.Conn, start time.Time) *xrecorder.HandlerRecorderObject {
	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Network:    "tcp",
		Time:       start,
		SID:        xctx.SidFromContext(ctx).String(),
	}
	if srcAddr := xctx.SrcAddrFromContext(ctx); srcAddr != nil {
		ro.ClientAddr = srcAddr.String()
	}
	return ro
}

// checkRateLimit verifies that the remote address has not exceeded the
// configured connection rate limit. Returns true if allowed, or if no rate
// limiter is configured.
func (h *sniHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	if addr == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}
	return true
}
