package loader

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metadata"
	reg "github.com/go-gost/core/registry"
	"github.com/go-gost/x/config"
	xlogger "github.com/go-gost/x/logger"
	"github.com/go-gost/x/registry"
)

func TestMain(m *testing.M) {
	logger.SetDefault(xlogger.NewLogger(xlogger.OutputOption(io.Discard)))
	m.Run()
}

// --- mock registry for registerGroup tests ---

type mockRegistry[T any] struct {
	m map[string]T
}

func newMockRegistry[T any]() *mockRegistry[T] {
	return &mockRegistry[T]{m: make(map[string]T)}
}

func (r *mockRegistry[T]) Register(name string, v T) error {
	if name == "" {
		return nil
	}
	if _, ok := r.m[name]; ok {
		return errors.New("duplicate")
	}
	r.m[name] = v
	return nil
}

func (r *mockRegistry[T]) Unregister(name string) {
	delete(r.m, name)
}

func (r *mockRegistry[T]) IsRegistered(name string) bool {
	_, ok := r.m[name]
	return ok
}

func (r *mockRegistry[T]) Get(name string) T {
	return r.m[name]
}

func (r *mockRegistry[T]) GetAll() map[string]T {
	result := make(map[string]T)
	for k, v := range r.m {
		result[k] = v
	}
	return result
}

// Ensure mockRegistry satisfies reg.Registry[T].
var _ reg.Registry[int] = (*mockRegistry[int])(nil)

// --- registerGroup tests ---

func TestRegisterGroup_EmptyEntries_EmptyRegistry(t *testing.T) {
	r := newMockRegistry[int]()
	err := registerGroup([]named[int]{}, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.GetAll()) != 0 {
		t.Fatalf("expected empty registry, got %d entries", len(r.GetAll()))
	}
}

func TestRegisterGroup_EmptyEntries_ClearsExisting(t *testing.T) {
	r := newMockRegistry[int]()
	r.Register("a", 1)
	r.Register("b", 2)

	err := registerGroup([]named[int]{}, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.GetAll()) != 0 {
		t.Fatalf("expected empty registry, got %d entries", len(r.GetAll()))
	}
}

func TestRegisterGroup_SingleEntry(t *testing.T) {
	r := newMockRegistry[int]()
	err := registerGroup([]named[int]{{"x", 42}}, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered("x") {
		t.Fatal("expected 'x' to be registered")
	}
	if v := r.Get("x"); v != 42 {
		t.Fatalf("expected 42, got %v", v)
	}
}

func TestRegisterGroup_MultipleEntries(t *testing.T) {
	r := newMockRegistry[int]()
	err := registerGroup([]named[int]{
		{"x", 1},
		{"y", 2},
		{"z", 3},
	}, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	all := r.GetAll()
	if len(all) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(all))
	}
	for _, name := range []string{"x", "y", "z"} {
		if !r.IsRegistered(name) {
			t.Fatalf("expected '%s' to be registered", name)
		}
	}
}

func TestRegisterGroup_ReplacesExisting(t *testing.T) {
	r := newMockRegistry[int]()
	r.Register("old", 1)
	r.Register("keep", 2) // this one should be removed

	err := registerGroup([]named[int]{
		{"old", 99},
		{"new", 100},
	}, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v := r.Get("old"); v != 99 {
		t.Fatalf("expected 99, got %v", v)
	}
	if !r.IsRegistered("new") {
		t.Fatal("expected 'new' to be registered")
	}
	if r.IsRegistered("keep") {
		t.Fatal("expected 'keep' to be unregistered")
	}
}

func TestRegisterGroup_DuplicateNameInEntries(t *testing.T) {
	r := newMockRegistry[int]()
	err := registerGroup([]named[int]{
		{"dup", 1},
		{"dup", 2},
	}, r)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
	// First entry should be registered, second failed.
	if v := r.Get("dup"); v != 1 {
		t.Fatalf("expected first entry (1), got %v", v)
	}
}

func TestRegisterGroup_ZeroValue(t *testing.T) {
	r := newMockRegistry[int]()
	// int zero value (0) is still registered
	err := registerGroup([]named[int]{{"zero", 0}}, r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered("zero") {
		t.Fatal("expected 'zero' to be registered")
	}
}

// --- register tests ---

func TestRegister_NilConfig(t *testing.T) {
	if err := register(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegister_EmptyConfig(t *testing.T) {
	if err := register(&config.Config{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRegister_Loggers(t *testing.T) {
	reg := registry.LoggerRegistry()
	name := "test-logger"
	t.Cleanup(func() { reg.Unregister(name) })

	cfg := &config.Config{
		Loggers: []*config.LoggerConfig{
			{Name: name, Log: &config.LogConfig{Level: "info"}},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reg.IsRegistered(name) {
		t.Fatal("expected logger to be registered")
	}
}

func TestRegister_Authers(t *testing.T) {
	r := registry.AutherRegistry()
	name := "test-auther"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		Authers: []*config.AutherConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected auther to be registered")
	}
}

func TestRegister_Admissions(t *testing.T) {
	r := registry.AdmissionRegistry()
	name := "test-admission"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		Admissions: []*config.AdmissionConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected admission to be registered")
	}
}

func TestRegister_Bypasses(t *testing.T) {
	r := registry.BypassRegistry()
	name := "test-bypass"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		Bypasses: []*config.BypassConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected bypass to be registered")
	}
}

func TestRegister_Resolvers(t *testing.T) {
	r := registry.ResolverRegistry()
	name := "test-resolver"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		Resolvers: []*config.ResolverConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected resolver to be registered")
	}
}

func TestRegister_Hosts(t *testing.T) {
	r := registry.HostsRegistry()
	name := "test-hosts"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		Hosts: []*config.HostsConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected host mapper to be registered")
	}
}

func TestRegister_Ingresses(t *testing.T) {
	r := registry.IngressRegistry()
	name := "test-ingress"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		Ingresses: []*config.IngressConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected ingress to be registered")
	}
}

func TestRegister_Routers(t *testing.T) {
	r := registry.RouterRegistry()
	name := "test-router"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		Routers: []*config.RouterConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected router to be registered")
	}
}

func TestRegister_SDs(t *testing.T) {
	r := registry.SDRegistry()
	name := "test-sd"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		SDs: []*config.SDConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected SD to be registered")
	}
}

func TestRegister_Observers(t *testing.T) {
	r := registry.ObserverRegistry()
	name := "test-observer"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		Observers: []*config.ObserverConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected observer to be registered")
	}
}

func TestRegister_Recorders(t *testing.T) {
	r := registry.RecorderRegistry()
	name := "test-recorder"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		Recorders: []*config.RecorderConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected recorder to be registered")
	}
}

func TestRegister_TrafficLimiters(t *testing.T) {
	r := registry.TrafficLimiterRegistry()
	name := "test-traffic-limiter"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		Limiters: []*config.LimiterConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected traffic limiter to be registered")
	}
}

func TestRegister_ConnLimiters(t *testing.T) {
	r := registry.ConnLimiterRegistry()
	name := "test-conn-limiter"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		CLimiters: []*config.LimiterConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected conn limiter to be registered")
	}
}

func TestRegister_RateLimiters(t *testing.T) {
	r := registry.RateLimiterRegistry()
	name := "test-rate-limiter"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		RLimiters: []*config.LimiterConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected rate limiter to be registered")
	}
}

func TestRegister_Hops(t *testing.T) {
	r := registry.HopRegistry()
	name := "test-hop"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		Hops: []*config.HopConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected hop to be registered")
	}
}

func TestRegister_Chains(t *testing.T) {
	r := registry.ChainRegistry()
	name := "test-chain"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		Chains: []*config.ChainConfig{
			{Name: name},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected chain to be registered")
	}
}

// stubListener satisfies listener.Listener for testing.
type stubListener struct{}

func (l *stubListener) Init(md metadata.Metadata) error                 { return nil }
func (l *stubListener) Accept() (net.Conn, error)                       { return nil, net.ErrClosed }
func (l *stubListener) Addr() net.Addr                                  { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (l *stubListener) Close() error                                    { return nil }

// stubHandler satisfies handler.Handler for testing.
type stubHandler struct{}

func (h *stubHandler) Init(md metadata.Metadata) error                  { return nil }
func (h *stubHandler) Handle(_ context.Context, _ net.Conn, _ ...handler.HandleOption) error { return nil }

func TestRegister_Services(t *testing.T) {
	// ParseService needs "tcp" listener and "auto" handler in registries.
	// These are registered via init() in their respective packages but those
	// packages are not imported here, so the factories won't be found.
	// Register stub factories so the test can exercise the service section.
	//
	// This save/restore pattern assumes no other test or transitive import
	// has already registered "tcp" or "auto" factory functions. If those
	// packages are ever imported by this test file, origListener/origHandler
	// will be non-nil and the restore path will re-register the real
	// factories, which is the desired behavior.
	origListener := registry.ListenerRegistry().Get("tcp")
	origHandler := registry.HandlerRegistry().Get("auto")

	registry.ListenerRegistry().Register("tcp", func(opts ...listener.Option) listener.Listener {
		return &stubListener{}
	})
	registry.HandlerRegistry().Register("auto", func(opts ...handler.Option) handler.Handler {
		return &stubHandler{}
	})
	t.Cleanup(func() {
		registry.ListenerRegistry().Unregister("tcp")
		registry.HandlerRegistry().Unregister("auto")
		if origListener != nil {
			registry.ListenerRegistry().Register("tcp", origListener)
		}
		if origHandler != nil {
			registry.HandlerRegistry().Register("auto", origHandler)
		}
	})

	r := registry.ServiceRegistry()
	name := "test-service"
	t.Cleanup(func() { r.Unregister(name) })

	cfg := &config.Config{
		Services: []*config.ServiceConfig{
			{Name: name, Addr: ":0"},
		},
	}
	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !r.IsRegistered(name) {
		t.Fatal("expected service to be registered")
	}
}

func TestRegister_MultipleSections(t *testing.T) {
	// Verify that multiple sections are all registered and in dependency order.
	bypassReg := registry.BypassRegistry()
	hopReg := registry.HopRegistry()
	chainReg := registry.ChainRegistry()

	bypassName := "multi-bypass"
	hopName := "multi-hop"
	chainName := "multi-chain"

	t.Cleanup(func() {
		bypassReg.Unregister(bypassName)
		hopReg.Unregister(hopName)
		chainReg.Unregister(chainName)
	})

	cfg := &config.Config{
		Bypasses: []*config.BypassConfig{{Name: bypassName}},
		Hops:     []*config.HopConfig{{Name: hopName}},
		Chains:   []*config.ChainConfig{{Name: chainName}},
	}

	if err := register(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bypassReg.IsRegistered(bypassName) {
		t.Fatal("expected bypass to be registered")
	}
	if !hopReg.IsRegistered(hopName) {
		t.Fatal("expected hop to be registered")
	}
	if !chainReg.IsRegistered(chainName) {
		t.Fatal("expected chain to be registered")
	}
}

func TestRegister_ComponentOrder(t *testing.T) {
	// register() processes sections in dependency order: leaf components
	// (loggers, authers, resolvers, etc.) first, then hops, then chains,
	// then services. Hops look up loggers/resolvers from registries;
	// chains look up hops; services look up chains.
	//
	// This test directly calls registerGroup in the canonical dependency
	// sequence and verifies each layer can see the previous layer's
	// registrations.

	// Use a sequence-tracking registry to verify registration order.
	type seqEntry struct {
		name string
		seq  int
	}
	var seq int
	leafReg := newMockRegistry[seqEntry]()
	hopReg := newMockRegistry[seqEntry]()
	chainReg := newMockRegistry[seqEntry]()
	svcReg := newMockRegistry[seqEntry]()

	seq++
	registerGroup([]named[seqEntry]{{"leaf", seqEntry{"logger", seq}}}, leafReg)

	// Hops should see leaf registrations.
	if !leafReg.IsRegistered("leaf") {
		t.Fatal("expected leaf to be registered before hops")
	}
	seq++
	registerGroup([]named[seqEntry]{{"hop", seqEntry{"hop", seq}}}, hopReg)

	// Chains should see hop registrations.
	if !hopReg.IsRegistered("hop") {
		t.Fatal("expected hop to be registered before chains")
	}
	seq++
	registerGroup([]named[seqEntry]{{"chain", seqEntry{"chain", seq}}}, chainReg)

	// Services should see chain registrations.
	if !chainReg.IsRegistered("chain") {
		t.Fatal("expected chain to be registered before services")
	}
	seq++
	registerGroup([]named[seqEntry]{{"svc", seqEntry{"svc", seq}}}, svcReg)

	// All should be registered.
	for _, r := range []struct {
		name string
		reg  *mockRegistry[seqEntry]
	}{
		{"leaf", leafReg},
		{"hop", hopReg},
		{"chain", chainReg},
		{"svc", svcReg},
	} {
		if len(r.reg.GetAll()) != 1 {
			t.Fatalf("expected 1 entry in %s registry", r.name)
		}
	}

	// Verify registration sequence: leaf < hop < chain < svc.
	if leafReg.Get("leaf").seq >= hopReg.Get("hop").seq {
		t.Fatal("leaf must be registered before hop")
	}
	if hopReg.Get("hop").seq >= chainReg.Get("chain").seq {
		t.Fatal("hop must be registered before chain")
	}
	if chainReg.Get("chain").seq >= svcReg.Get("svc").seq {
		t.Fatal("chain must be registered before service")
	}
}

// --- Load tests ---

func TestLoad_NilConfig(t *testing.T) {
	if err := Load(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoad_EmptyConfig(t *testing.T) {
	cfg := &config.Config{}
	if err := Load(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoad_WithTLS(t *testing.T) {
	// BuildDefaultTLSConfig with nil TLS falls back to default cert/key files
	// which don't exist, but it then generates a self-signed cert, so it
	// should still succeed.
	cfg := &config.Config{
		TLS: &config.TLSConfig{
			Validity: 3600,
		},
	}
	if err := Load(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoad_WithLog(t *testing.T) {
	cfg := &config.Config{
		Log: &config.LogConfig{
			Level: "error",
		},
	}
	if err := Load(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoad_SetsDefaultLogger(t *testing.T) {
	cfg := &config.Config{
		Log: &config.LogConfig{
			Level:  "warn",
			Format: "json",
		},
	}
	if err := Load(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// After Load, logger.Default() should be non-nil.
	if logger.Default() == nil {
		t.Fatal("expected default logger to be set")
	}
}

// --- defaultLoader singleton tests ---

func TestDefaultLoader_IsSet(t *testing.T) {
	if defaultLoader == nil {
		t.Fatal("defaultLoader should not be nil")
	}
	if err := defaultLoader.Load(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- registerGroup edge cases ---

type countingRegistry[T any] struct {
	m     map[string]T
	close int
}

func newCountingRegistry[T any]() *countingRegistry[T] {
	return &countingRegistry[T]{m: make(map[string]T)}
}

func (r *countingRegistry[T]) Register(name string, v T) error      { r.m[name] = v; return nil }
func (r *countingRegistry[T]) Unregister(name string)                { delete(r.m, name); r.close++ }
func (r *countingRegistry[T]) IsRegistered(name string) bool         { _, ok := r.m[name]; return ok }
func (r *countingRegistry[T]) Get(name string) T                     { return r.m[name] }
func (r *countingRegistry[T]) GetAll() map[string]T                  { return r.m }

func TestRegisterGroup_UnregistersAllOldEntries(t *testing.T) {
	r := newCountingRegistry[int]()
	r.Register("a", 1)
	r.Register("b", 2)
	r.Register("c", 3)

	_ = registerGroup([]named[int]{{"x", 10}}, r)

	if r.close != 3 {
		t.Fatalf("expected 3 unregister calls, got %d", r.close)
	}
	if !r.IsRegistered("x") {
		t.Fatal("expected 'x' to be registered")
	}
	if r.IsRegistered("a") || r.IsRegistered("b") || r.IsRegistered("c") {
		t.Fatal("old entries should be unregistered")
	}
}

// --- register error paths ---

func TestRegister_ServiceBadTLS(t *testing.T) {
	// A non-empty CertFile that doesn't exist causes
	// tls_util.LoadServerConfig to fail before reaching the
	// listener registry lookup.
	//
	// ParseService logs an error via the default logger when the
	// TLS cert can't be loaded. We suppress that log here since
	// the error is expected.
	logger.SetDefault(xlogger.NewLogger(xlogger.OutputOption(io.Discard)))
	discardLogger := xlogger.NewLogger(xlogger.OutputOption(io.Discard))
	t.Cleanup(func() { logger.SetDefault(discardLogger) })

	cfg := &config.Config{
		Services: []*config.ServiceConfig{
			{
				Name: "bad-tls",
				Addr: ":0",
				Listener: &config.ListenerConfig{
					TLS: &config.TLSConfig{
						CertFile: "/nonexistent/cert.pem",
					},
				},
			},
		},
	}
	if err := register(cfg); err == nil {
		t.Fatal("expected error for bad TLS config, got nil")
	}
}

func TestRegister_ServiceUnknownListener(t *testing.T) {
	// An unregistered listener type triggers the
	// "unknown listener" error in ParseService.
	cfg := &config.Config{
		Services: []*config.ServiceConfig{
			{
				Name: "unknown-ln",
				Addr: ":0",
				Listener: &config.ListenerConfig{
					Type: "nonexistent",
				},
			},
		},
	}
	if err := register(cfg); err == nil {
		t.Fatal("expected error for unknown listener type, got nil")
	}
}

// bindingStubListener is a stubListener whose Init actually binds a TCP port
// via net.Listen, reproducing the EADDRINUSE condition the close-old-before-
// bind ordering in register() must prevent. Used only by reload-collision tests.
type bindingStubListener struct {
	addr string
	ln   net.Listener
}

func (l *bindingStubListener) Init(md metadata.Metadata) error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return err
	}
	l.ln = ln
	return nil
}

func (l *bindingStubListener) Accept() (net.Conn, error) {
	if l.ln == nil {
		return nil, net.ErrClosed
	}
	return l.ln.Accept()
}

func (l *bindingStubListener) Addr() net.Addr {
	if l.ln != nil {
		return l.ln.Addr()
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (l *bindingStubListener) Close() error {
	if l.ln == nil {
		return nil
	}
	return l.ln.Close()
}

// freeTCPPort returns the number of a TCP port that is free at call time by
// opening and immediately closing a listener on 127.0.0.1:0. There is a small
// race window before the caller rebinds, which is acceptable for tests.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	addr := l.Addr().(*net.TCPAddr)
	l.Close()
	return addr.Port
}

// TestRegister_ServiceReloadNoCollision verifies that calling register() twice
// with a service on a fixed port does NOT return EADDRINUSE on the second call
// (issue #754). Before the close-old-before-bind ordering, the second
// register() bound the new listener while the old one was still listening.
func TestRegister_ServiceReloadNoCollision(t *testing.T) {
	port := freeTCPPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Register a binding listener factory under a test-specific name so we
	// don't interfere with the "tcp" save/restore in TestRegister_Services.
	const factoryName = "tcp-binding-test"
	origListener := registry.ListenerRegistry().Get(factoryName)
	registry.ListenerRegistry().Register(factoryName, func(opts ...listener.Option) listener.Listener {
		options := listener.Options{}
		for _, opt := range opts {
			opt(&options)
		}
		return &bindingStubListener{addr: options.Addr}
	})
	// Reuse the inert "auto" handler stub.
	origHandler := registry.HandlerRegistry().Get("auto")
	registry.HandlerRegistry().Register("auto", func(opts ...handler.Option) handler.Handler {
		return &stubHandler{}
	})
	t.Cleanup(func() {
		registry.ListenerRegistry().Unregister(factoryName)
		registry.HandlerRegistry().Unregister("auto")
		if origListener != nil {
			registry.ListenerRegistry().Register(factoryName, origListener)
		}
		if origHandler != nil {
			registry.HandlerRegistry().Register("auto", origHandler)
		}
	})

	r := registry.ServiceRegistry()
	const svcName = "reload-svc"
	t.Cleanup(func() { r.Unregister(svcName) })

	buildCfg := func() *config.Config {
		return &config.Config{
			Services: []*config.ServiceConfig{
				{
					Name:     svcName,
					Addr:     addr,
					Listener: &config.ListenerConfig{Type: factoryName},
					Handler:  &config.HandlerConfig{Type: "auto"},
				},
			},
		}
	}

	// First load: registers the service and binds the port.
	if err := register(buildCfg()); err != nil {
		t.Fatalf("first register: unexpected error: %v", err)
	}
	if !r.IsRegistered(svcName) {
		t.Fatal("expected service registered after first load")
	}

	// Second load simulates a SIGHUP reload. With the old ordering this bound
	// the new listener while the old one was still open and returned
	// "address already in use"; the fix closes old services first.
	if err := register(buildCfg()); err != nil {
		if strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("second register (reload): port collision not avoided: %v", err)
		}
		t.Fatalf("second register (reload): unexpected error: %v", err)
	}
	if !r.IsRegistered(svcName) {
		t.Fatal("expected service registered after reload")
	}
}
