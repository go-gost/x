package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/core/router"
	"github.com/go-gost/x/internal/loader"
	xlogger "github.com/go-gost/x/logger"
)

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

// closeRouter closes a router if it implements io.Closer.
func closeRouter(r router.Router) {
	if c, ok := r.(interface{ Close() error }); ok {
		c.Close()
	}
}

// mockLoader implements loader.Loader for testing.
type mockLoader struct {
	data   string
	err    error
	closed bool
}

func (m *mockLoader) Load(_ context.Context) (io.Reader, error) {
	if m.err != nil {
		return nil, m.err
	}
	return strings.NewReader(m.data), nil
}

func (m *mockLoader) Close() error {
	m.closed = true
	return nil
}

// mockLister implements both loader.Loader and loader.Lister.
type mockLister struct {
	lines  []string
	loadOk bool // if true, Load also works
	closed bool
}

func (m *mockLister) Load(_ context.Context) (io.Reader, error) {
	return strings.NewReader(strings.Join(m.lines, "\n")), nil
}

func (m *mockLister) List(_ context.Context) ([]string, error) {
	return m.lines, nil
}

func (m *mockLister) Close() error {
	m.closed = true
	return nil
}

// errLoader always fails to load.
type errLoader struct {
	closed bool
}

func (e *errLoader) Load(_ context.Context) (io.Reader, error) {
	return nil, errors.New("load failed")
}

func (e *errLoader) Close() error {
	e.closed = true
	return nil
}

// errLister always fails to list.
type errLister struct {
	closed bool
}

func (e *errLister) Load(_ context.Context) (io.Reader, error) {
	return nil, errors.New("load failed")
}

func (e *errLister) List(_ context.Context) ([]string, error) {
	return nil, errors.New("list failed")
}

func (e *errLister) Close() error {
	e.closed = true
	return nil
}

// ---------------------------------------------------------------------------
// ParseRoute tests
// ---------------------------------------------------------------------------

func TestParseRoute_CIDR(t *testing.T) {
	r := ParseRoute("10.0.0.0/8", "192.168.1.1")
	if r == nil {
		t.Fatal("expected non-nil route")
	}
	if r.Dst != "10.0.0.0/8" {
		t.Errorf("Dst = %q, want %q", r.Dst, "10.0.0.0/8")
	}
	if r.Gateway != "192.168.1.1" {
		t.Errorf("Gateway = %q, want %q", r.Gateway, "192.168.1.1")
	}
	if r.Net == nil {
		t.Fatal("expected non-nil Net for CIDR")
	}
	if !r.Net.Contains(net.ParseIP("10.1.2.3")) {
		t.Error("Net should contain 10.1.2.3")
	}
}

func TestParseRoute_EmptyDst(t *testing.T) {
	if r := ParseRoute("", "1.2.3.4"); r != nil {
		t.Errorf("expected nil for empty dst, got %+v", r)
	}
}

func TestParseRoute_InvalidCIDR(t *testing.T) {
	// Non-CIDR string: Net will be nil but route is still returned
	r := ParseRoute("not-a-cidr", "1.2.3.4")
	if r == nil {
		t.Fatal("expected non-nil route even for invalid CIDR")
	}
	if r.Net != nil {
		t.Error("expected nil Net for invalid CIDR")
	}
	if r.Dst != "not-a-cidr" {
		t.Errorf("Dst = %q, want %q", r.Dst, "not-a-cidr")
	}
}

func TestParseRoute_PlainIP(t *testing.T) {
	r := ParseRoute("192.168.1.0", "10.0.0.1")
	if r == nil {
		t.Fatal("expected non-nil route")
	}
	if r.Net != nil {
		t.Error("expected nil Net for plain IP (not CIDR)")
	}
}

// ---------------------------------------------------------------------------
// parseLine tests
// ---------------------------------------------------------------------------

func TestParseLine_Valid(t *testing.T) {
	lr := &localRouter{}
	r := lr.parseLine("10.0.0.0/8 192.168.1.1")
	if r == nil {
		t.Fatal("expected non-nil route")
	}
	if r.Dst != "10.0.0.0/8" {
		t.Errorf("Dst = %q", r.Dst)
	}
	if r.Gateway != "192.168.1.1" {
		t.Errorf("Gateway = %q", r.Gateway)
	}
}

func TestParseLine_TabSeparated(t *testing.T) {
	lr := &localRouter{}
	r := lr.parseLine("10.0.0.0/8\t192.168.1.1")
	if r == nil {
		t.Fatal("tabs should be treated as separators")
	}
	if r.Dst != "10.0.0.0/8" {
		t.Errorf("Dst = %q", r.Dst)
	}
}

func TestParseLine_Comment(t *testing.T) {
	lr := &localRouter{}
	r := lr.parseLine("10.0.0.0/8 192.168.1.1 # default route")
	if r == nil {
		t.Fatal("expected non-nil route, comment should be stripped")
	}
}

func TestParseLine_CommentOnly(t *testing.T) {
	lr := &localRouter{}
	if r := lr.parseLine("# just a comment"); r != nil {
		t.Errorf("comment-only line should return nil, got %+v", r)
	}
}

func TestParseLine_Empty(t *testing.T) {
	lr := &localRouter{}
	if r := lr.parseLine(""); r != nil {
		t.Errorf("empty line should return nil")
	}
	if r := lr.parseLine("   "); r != nil {
		t.Errorf("whitespace line should return nil")
	}
}

func TestParseLine_TooFewFields(t *testing.T) {
	lr := &localRouter{}
	if r := lr.parseLine("10.0.0.0/8"); r != nil {
		t.Errorf("single field should return nil")
	}
}

func TestParseLine_ExtraSpaces(t *testing.T) {
	lr := &localRouter{}
	r := lr.parseLine("  10.0.0.0/8    192.168.1.1  ")
	if r == nil {
		t.Fatal("extra whitespace should be trimmed")
	}
	if r.Dst != "10.0.0.0/8" {
		t.Errorf("Dst = %q", r.Dst)
	}
}

// ---------------------------------------------------------------------------
// parseRoutes tests
// ---------------------------------------------------------------------------

func TestParseRoutes_Valid(t *testing.T) {
	lr := &localRouter{}
	input := "10.0.0.0/8 192.168.1.1\n172.16.0.0/12 10.0.0.1\n"
	routes, err := lr.parseRoutes(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}
	if routes[0].Dst != "10.0.0.0/8" {
		t.Errorf("routes[0].Dst = %q", routes[0].Dst)
	}
	if routes[1].Dst != "172.16.0.0/12" {
		t.Errorf("routes[1].Dst = %q", routes[1].Dst)
	}
}

func TestParseRoutes_NilReader(t *testing.T) {
	lr := &localRouter{}
	routes, err := lr.parseRoutes(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Errorf("expected 0 routes for nil reader, got %d", len(routes))
	}
}

func TestParseRoutes_MixedContent(t *testing.T) {
	lr := &localRouter{}
	input := "# header\n10.0.0.0/8 192.168.1.1\n\n# comment\n172.16.0.0/12 10.0.0.1\nbadline\n"
	routes, err := lr.parseRoutes(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 valid routes (skipping blanks/comments/single-field), got %d", len(routes))
	}
}

// errReader is an io.Reader that always errors.
type errReader struct{}

func (errReader) Read(_ []byte) (int, error) { return 0, errors.New("read error") }

func TestParseRoutes_ScannerError(t *testing.T) {
	lr := &localRouter{}
	routes, err := lr.parseRoutes(errReader{})
	if err == nil {
		t.Fatal("expected scanner error from failing reader")
	}
	if len(routes) != 0 {
		t.Errorf("expected 0 routes on error, got %d", len(routes))
	}
}

// ---------------------------------------------------------------------------
// GetRoute tests
// ---------------------------------------------------------------------------

func TestNewRouter_StaticRoutes(t *testing.T) {
	r := NewRouter(
		RoutesOption([]*router.Route{
			{Dst: "10.0.0.0/8", Gateway: "192.168.1.1", Net: mustCIDR("10.0.0.0/8")},
			{Dst: "172.16.0.0/12", Gateway: "10.0.0.1", Net: mustCIDR("172.16.0.0/12")},
		}),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	ctx := context.Background()

	// Exact match
	route := r.GetRoute(ctx, "10.0.0.0/8")
	if route == nil {
		t.Fatal("expected route for exact dst match")
	}
	if route.Gateway != "192.168.1.1" {
		t.Errorf("Gateway = %q, want %q", route.Gateway, "192.168.1.1")
	}

	// CIDR containment match
	route = r.GetRoute(ctx, "10.1.2.3")
	if route == nil {
		t.Fatal("expected route for IP within 10.0.0.0/8")
	}
	if route.Gateway != "192.168.1.1" {
		t.Errorf("Gateway = %q, want %q", route.Gateway, "192.168.1.1")
	}

	// No match
	route = r.GetRoute(ctx, "8.8.8.8")
	if route != nil {
		t.Errorf("expected nil for unmatched IP, got %+v", route)
	}
}

func TestGetRoute_EmptyDst(t *testing.T) {
	r := NewRouter(LoggerOption(xlogger.Nop()))
	defer closeRouter(r)

	if route := r.GetRoute(context.Background(), ""); route != nil {
		t.Errorf("expected nil for empty dst")
	}
}

func TestGetRoute_NilReceiver(t *testing.T) {
	var r *localRouter
	if route := r.GetRoute(context.Background(), "10.0.0.1"); route != nil {
		t.Errorf("expected nil for nil receiver")
	}
}

func TestGetRoute_NilNet(t *testing.T) {
	r := NewRouter(
		RoutesOption([]*router.Route{
			{Dst: "192.168.1.0", Gateway: "10.0.0.1", Net: nil},
		}),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	// Should match by exact Dst string
	route := r.GetRoute(context.Background(), "192.168.1.0")
	if route == nil {
		t.Fatal("expected route for exact Dst match with nil Net")
	}
	if route.Gateway != "10.0.0.1" {
		t.Errorf("Gateway = %q", route.Gateway)
	}

	// Should NOT match by CIDR since Net is nil
	route = r.GetRoute(context.Background(), "192.168.1.100")
	if route != nil {
		t.Errorf("expected nil — Net is nil so CIDR containment can't match")
	}
}

func TestGetRoute_IPv6CIDR(t *testing.T) {
	r := NewRouter(
		RoutesOption([]*router.Route{
			{Dst: "fd00::/8", Gateway: "fe80::1", Net: mustCIDR("fd00::/8")},
		}),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	route := r.GetRoute(context.Background(), "fd00:dead:beef::1")
	if route == nil {
		t.Fatal("expected route for IPv6 in fd00::/8")
	}
	if route.Gateway != "fe80::1" {
		t.Errorf("Gateway = %q", route.Gateway)
	}
}

// ---------------------------------------------------------------------------
// Loader integration tests
// ---------------------------------------------------------------------------

func TestNewRouter_FileLoader(t *testing.T) {
	fl := &mockLoader{
		data: "10.0.0.0/8 192.168.1.1\n172.16.0.0/12 10.0.0.1\n",
	}
	r := NewRouter(
		FileLoaderOption(fl),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	route := r.GetRoute(context.Background(), "10.5.5.5")
	if route == nil {
		t.Fatal("expected route loaded from file loader")
	}
	if route.Gateway != "192.168.1.1" {
		t.Errorf("Gateway = %q", route.Gateway)
	}
}

func TestNewRouter_FileLoaderLister(t *testing.T) {
	fl := &mockLister{
		lines: []string{"10.0.0.0/8 192.168.1.1", "172.16.0.0/12 10.0.0.1"},
	}
	r := NewRouter(
		FileLoaderOption(fl),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	route := r.GetRoute(context.Background(), "172.20.0.1")
	if route == nil {
		t.Fatal("expected route from lister-based file loader")
	}
	if route.Gateway != "10.0.0.1" {
		t.Errorf("Gateway = %q", route.Gateway)
	}
}

func TestNewRouter_RedisLoader(t *testing.T) {
	rl := &mockLoader{
		data: "192.168.0.0/16 10.0.0.1\n",
	}
	r := NewRouter(
		RedisLoaderOption(rl),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	route := r.GetRoute(context.Background(), "192.168.99.99")
	if route == nil {
		t.Fatal("expected route from redis loader")
	}
}

func TestNewRouter_HTTPLoader(t *testing.T) {
	hl := &mockLoader{
		data: "10.10.0.0/16 172.16.0.1\n",
	}
	r := NewRouter(
		HTTPLoaderOption(hl),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	route := r.GetRoute(context.Background(), "10.10.5.5")
	if route == nil {
		t.Fatal("expected route from http loader")
	}
}

func TestNewRouter_AllLoaders(t *testing.T) {
	fl := &mockLoader{data: "10.0.0.0/8 gw-file\n"}
	rl := &mockLoader{data: "172.16.0.0/12 gw-redis\n"}
	hl := &mockLoader{data: "192.168.0.0/16 gw-http\n"}

	r := NewRouter(
		FileLoaderOption(fl),
		RedisLoaderOption(rl),
		HTTPLoaderOption(hl),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	tests := []struct {
		dst, wantGW string
	}{
		{"10.1.2.3", "gw-file"},
		{"172.20.0.1", "gw-redis"},
		{"192.168.1.1", "gw-http"},
	}
	for _, tc := range tests {
		route := r.GetRoute(context.Background(), tc.dst)
		if route == nil {
			t.Fatalf("expected route for %s", tc.dst)
		}
		if route.Gateway != tc.wantGW {
			t.Errorf("GetRoute(%s).Gateway = %q, want %q", tc.dst, route.Gateway, tc.wantGW)
		}
	}
}

func TestNewRouter_StaticPlusLoader(t *testing.T) {
	fl := &mockLoader{data: "10.0.0.0/8 gw-dynamic\n"}
	static := []*router.Route{
		{Dst: "172.16.0.0/12", Gateway: "gw-static", Net: mustCIDR("172.16.0.0/12")},
	}

	r := NewRouter(
		RoutesOption(static),
		FileLoaderOption(fl),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	// Dynamic route
	route := r.GetRoute(context.Background(), "10.0.0.1")
	if route == nil || route.Gateway != "gw-dynamic" {
		t.Errorf("expected gw-dynamic for 10.0.0.1, got %+v", route)
	}

	// Static route
	route = r.GetRoute(context.Background(), "172.20.0.1")
	if route == nil || route.Gateway != "gw-static" {
		t.Errorf("expected gw-static for 172.20.0.1, got %+v", route)
	}
}

// ---------------------------------------------------------------------------
// Error handling tests
// ---------------------------------------------------------------------------

func TestNewRouter_LoaderError(t *testing.T) {
	el := &errLoader{}
	// Should not panic, just log the error
	r := NewRouter(
		FileLoaderOption(el),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	// No routes loaded
	route := r.GetRoute(context.Background(), "10.0.0.1")
	if route != nil {
		t.Errorf("expected nil route when loader fails")
	}
}

func TestNewRouter_ListerError(t *testing.T) {
	el := &errLister{}
	r := NewRouter(
		FileLoaderOption(el),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	route := r.GetRoute(context.Background(), "10.0.0.1")
	if route != nil {
		t.Errorf("expected nil route when lister fails")
	}
}

func TestNewRouter_NilLogger(t *testing.T) {
	// Should not panic when no logger is provided
	r := NewRouter(
		RoutesOption([]*router.Route{
			{Dst: "10.0.0.0/8", Gateway: "192.168.1.1", Net: mustCIDR("10.0.0.0/8")},
		}),
	)
	defer closeRouter(r)

	route := r.GetRoute(context.Background(), "10.0.0.1")
	if route == nil {
		t.Fatal("expected route even without logger")
	}
}

// ---------------------------------------------------------------------------
// Close tests
// ---------------------------------------------------------------------------

func TestClose_ClosesAllLoaders(t *testing.T) {
	fl := &mockLoader{}
	rl := &mockLoader{}
	hl := &mockLoader{}

	r := NewRouter(
		FileLoaderOption(fl),
		RedisLoaderOption(rl),
		HTTPLoaderOption(hl),
		LoggerOption(xlogger.Nop()),
	)

	if err := r.(*localRouter).Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	if !fl.closed {
		t.Error("fileLoader not closed")
	}
	if !rl.closed {
		t.Error("redisLoader not closed")
	}
	if !hl.closed {
		t.Error("httpLoader not closed")
	}
}

func TestClose_NoLoaders(t *testing.T) {
	r := NewRouter(LoggerOption(xlogger.Nop()))
	if err := r.(*localRouter).Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Periodic reload tests
// ---------------------------------------------------------------------------

func TestPeriodReload(t *testing.T) {
	fl := &mockLoader{data: "10.0.0.0/8 gw-v1\n"}

	r := NewRouter(
		FileLoaderOption(fl),
		ReloadPeriodOption(50*time.Millisecond),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	// Initial load
	route := r.GetRoute(context.Background(), "10.0.0.1")
	if route == nil || route.Gateway != "gw-v1" {
		t.Fatalf("initial: got %+v", route)
	}

	// Update loader data and poll for reload (period clamped to >=1s)
	fl.data = "10.0.0.0/8 gw-v2\n"
	deadline := time.After(3 * time.Second)
	for {
		route = r.GetRoute(context.Background(), "10.0.0.1")
		if route != nil && route.Gateway == "gw-v2" {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for reload, got %+v", route)
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func TestPeriodReload_StopsOnCancel(t *testing.T) {
	fl := &mockLoader{data: "10.0.0.0/8 gw\n"}
	r := NewRouter(
		FileLoaderOption(fl),
		ReloadPeriodOption(50*time.Millisecond),
		LoggerOption(xlogger.Nop()),
	)

	// Close cancels the context
	r.(*localRouter).Close()

	// Update data after close — should not be picked up
	fl.data = "10.0.0.0/8 gw-updated\n"
	time.Sleep(150 * time.Millisecond)

	route := r.GetRoute(context.Background(), "10.0.0.1")
	if route != nil && route.Gateway == "gw-updated" {
		t.Error("route should not update after Close()")
	}
}

func TestReloadPeriodOption_MinimumClamp(t *testing.T) {
	// Period below 1s should be clamped to 1s internally
	fl := &mockLoader{data: "10.0.0.0/8 gw\n"}
	r := NewRouter(
		FileLoaderOption(fl),
		ReloadPeriodOption(1*time.Nanosecond),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	// Should still work — just won't reload faster than 1s
	route := r.GetRoute(context.Background(), "10.0.0.1")
	if route == nil {
		t.Fatal("expected route")
	}
}

// ---------------------------------------------------------------------------
// load() with nil reader from loader
// ---------------------------------------------------------------------------

func TestLoad_NilReaderOnError(t *testing.T) {
	el := &errLoader{}
	r := NewRouter(
		FileLoaderOption(el),
		LoggerOption(xlogger.Nop()),
	).(*localRouter)

	routes, err := r.load(context.Background())
	if err != nil {
		t.Fatalf("load should not return error for loader failures, got %v", err)
	}
	if len(routes) != 0 {
		t.Errorf("expected 0 routes, got %d", len(routes))
	}
}

func TestLoad_EmptyData(t *testing.T) {
	fl := &mockLoader{data: ""}
	r := NewRouter(
		FileLoaderOption(fl),
		LoggerOption(xlogger.Nop()),
	).(*localRouter)

	routes, err := r.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Errorf("expected 0 routes for empty data, got %d", len(routes))
	}
}

// ---------------------------------------------------------------------------
// parseRoutes nil reader guard
// ---------------------------------------------------------------------------

func TestParseRoutes_NilReaderNotAsserted(t *testing.T) {
	// Verify the nil guard works via the load path
	var fl loader.Loader = &nilReaderLoader{}
	r := NewRouter(
		FileLoaderOption(fl),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	// Should not panic
	route := r.GetRoute(context.Background(), "10.0.0.1")
	if route != nil {
		t.Errorf("expected nil route from nil reader loader")
	}
}

// nilReaderLoader returns a nil io.Reader.
type nilReaderLoader struct{}

func (n *nilReaderLoader) Load(_ context.Context) (io.Reader, error) { return nil, nil }
func (n *nilReaderLoader) Close() error                              { return nil }

// ---------------------------------------------------------------------------
// Context cancellation
// ---------------------------------------------------------------------------

func TestGetRoute_CancelledContext(t *testing.T) {
	r := NewRouter(
		RoutesOption([]*router.Route{
			{Dst: "10.0.0.0/8", Gateway: "192.168.1.1", Net: mustCIDR("10.0.0.0/8")},
		}),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// GetRoute doesn't use context internally (no IO), so cancelled ctx is fine
	route := r.GetRoute(ctx, "10.0.0.1")
	if route == nil {
		t.Fatal("GetRoute should still return route with cancelled context")
	}
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

func BenchmarkGetRoute(b *testing.B) {
	routes := make([]*router.Route, 100)
	for i := 0; i < 100; i++ {
		cidr := mustCIDR(fmt.Sprintf("10.%d.0.0/16", i))
		routes[i] = &router.Route{
			Dst:     fmt.Sprintf("10.%d.0.0/16", i),
			Gateway: fmt.Sprintf("192.168.%d.1", i),
			Net:     cidr,
		}
	}
	r := NewRouter(
		RoutesOption(routes),
		LoggerOption(xlogger.Nop()),
	)
	defer closeRouter(r)

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.GetRoute(ctx, "10.50.5.5")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustCIDR(s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipNet
}
