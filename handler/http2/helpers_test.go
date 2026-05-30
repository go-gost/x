package http2

import (
	"context"
	"net"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer"
	cmdata "github.com/go-gost/core/metadata"
	xmetadata "github.com/go-gost/x/metadata"
)

// --- Shared test helpers ---

type testLogger struct{}

func (l *testLogger) WithFields(map[string]any) logger.Logger   { return l }
func (l *testLogger) Debug(...any)                               {}
func (l *testLogger) Debugf(string, ...any)                      {}
func (l *testLogger) Info(...any)                                {}
func (l *testLogger) Infof(string, ...any)                       {}
func (l *testLogger) Warn(...any)                                {}
func (l *testLogger) Warnf(string, ...any)                       {}
func (l *testLogger) Error(...any)                               {}
func (l *testLogger) Errorf(string, ...any)                      {}
func (l *testLogger) Fatal(...any)                               {}
func (l *testLogger) Fatalf(string, ...any)                      {}
func (l *testLogger) GetLevel() logger.LogLevel                  { return logger.InfoLevel }
func (l *testLogger) IsLevelEnabled(logger.LogLevel) bool        { return false }
func (l *testLogger) Trace(...any)                               {}
func (l *testLogger) Tracef(string, ...any)                      {}

type testObserver struct{}

func (o *testObserver) Observe(context.Context, []observer.Event, ...observer.Option) error { return nil }

func testMD(m map[string]any) cmdata.Metadata { return xmetadata.NewMetadata(m) }

func newTestHandler(opts ...handler.Option) *http2Handler {
	options := handler.Options{Logger: &testLogger{}}
	for _, opt := range opts {
		opt(&options)
	}
	return &http2Handler{options: options}
}

// --- Stub types ---

type stubRateLimiter struct {
	allow bool
}

func newStubRateLimiter() *stubRateLimiter {
	return &stubRateLimiter{allow: true}
}

func (l *stubRateLimiter) Limiter(key string) rate.Limiter { return l }
func (l *stubRateLimiter) Allow(n int) bool                 { return l.allow }
func (l *stubRateLimiter) Limit() float64                   { return 0 }

type stubTrafficLimiter struct{}

func (l *stubTrafficLimiter) In(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	return l
}
func (l *stubTrafficLimiter) Out(ctx context.Context, key string, opts ...limiter.Option) traffic.Limiter {
	return l
}
func (l *stubTrafficLimiter) Wait(ctx context.Context, n int) int { return n }
func (l *stubTrafficLimiter) Limit() int                          { return 0 }
func (l *stubTrafficLimiter) Set(n int)                           {}

type stubRouter struct{}

func (r *stubRouter) Options() *chain.RouterOptions { return nil }
func (r *stubRouter) Dial(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
	return net.Dial(network, address)
}
func (r *stubRouter) Bind(ctx context.Context, network, address string, opts ...chain.BindOption) (net.Listener, error) {
	return nil, nil
}

type stubBypass struct {
	contains bool
}

func (b *stubBypass) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	return b.contains
}
