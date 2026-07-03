package registry

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/limiter"
	"github.com/go-gost/core/limiter/conn"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/recorder"
	reg "github.com/go-gost/core/registry"
	"github.com/go-gost/core/resolver"
	"github.com/go-gost/core/router"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/core/selector"
	"github.com/go-gost/core/service"
)

// --- Base registry[T] tests ---

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := new(registry[string])
	if err := r.Register("a", "alpha"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if v := r.Get("a"); v != "alpha" {
		t.Fatalf("Get(%q) = %q, want %q", "a", v, "alpha")
	}
}

func TestRegistry_RegisterEmptyName(t *testing.T) {
	r := new(registry[string])
	if err := r.Register("", "value"); err != nil {
		t.Fatalf("Register empty name: %v", err)
	}
	if r.IsRegistered("") {
		t.Fatal("empty name should not be registered")
	}
}

func TestRegistry_RegisterDuplicate(t *testing.T) {
	r := new(registry[int])
	if err := r.Register("x", 1); err != nil {
		t.Fatal(err)
	}
	if err := r.Register("x", 2); !errors.Is(err, ErrDup) {
		t.Fatalf("duplicate Register = %v, want ErrDup", err)
	}
	if v := r.Get("x"); v != 1 {
		t.Fatalf("Get after dup attempt = %d, want 1", v)
	}
}

func TestRegistry_GetUnknown(t *testing.T) {
	r := new(registry[string])
	if v := r.Get("missing"); v != "" {
		t.Fatalf("Get(unknown) = %q, want zero value", v)
	}
}

func TestRegistry_GetEmptyName(t *testing.T) {
	r := new(registry[int])
	r.Register("x", 42)
	if v := r.Get(""); v != 0 {
		t.Fatalf("Get(empty) = %d, want 0", v)
	}
}

func TestRegistry_GetAll(t *testing.T) {
	r := new(registry[string])
	r.Register("a", "alpha")
	r.Register("b", "beta")
	m := r.GetAll()
	if len(m) != 2 {
		t.Fatalf("GetAll len = %d, want 2", len(m))
	}
	if m["a"] != "alpha" || m["b"] != "beta" {
		t.Fatalf("GetAll = %v", m)
	}
}

func TestRegistry_GetAllEmpty(t *testing.T) {
	r := new(registry[int])
	m := r.GetAll()
	if m == nil || len(m) != 0 {
		t.Fatalf("GetAll on empty = %v, want empty non-nil map", m)
	}
}

func TestRegistry_IsRegistered(t *testing.T) {
	r := new(registry[string])
	r.Register("k", "v")
	if !r.IsRegistered("k") {
		t.Fatal("IsRegistered(k) = false, want true")
	}
	if r.IsRegistered("nope") {
		t.Fatal("IsRegistered(nope) = true, want false")
	}
}

func TestRegistry_Unregister(t *testing.T) {
	r := new(registry[string])
	r.Register("x", "val")
	r.Unregister("x")
	if r.IsRegistered("x") {
		t.Fatal("still registered after Unregister")
	}
	if v := r.Get("x"); v != "" {
		t.Fatalf("Get after unregister = %q, want zero", v)
	}
}

func TestRegistry_UnregisterUnknown(t *testing.T) {
	r := new(registry[string])
	r.Unregister("nope") // should not panic
}

type closeableService struct {
	closed bool
}

func (s *closeableService) Serve() error        { return nil }
func (s *closeableService) Addr() net.Addr      { return nil }
func (s *closeableService) Close() error {
	s.closed = true
	return nil
}

func TestRegistry_UnregisterCloses(t *testing.T) {
	r := new(registry[service.Service])
	svc := &closeableService{}
	r.Register("svc", svc)
	r.Unregister("svc")
	if !svc.closed {
		t.Fatal("Unregister did not call Close on io.Closer")
	}
}

type closeErrService struct{}

func (s *closeErrService) Serve() error   { return nil }
func (s *closeErrService) Addr() net.Addr { return nil }
func (s *closeErrService) Close() error   { return errors.New("close err") }

func TestRegistry_UnregisterCloseError(t *testing.T) {
	logger.SetDefault(&mockLogger{})
	r := new(registry[service.Service])
	svc := &closeErrService{}
	r.Register("svc", svc)
	r.Unregister("svc") // logs error but should not panic
	if r.IsRegistered("svc") {
		t.Fatal("should be unregistered even if Close errors")
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := new(registry[int])
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := string(rune('a' + i%26))
			r.Register(name, i)
			r.Get(name)
			r.IsRegistered(name)
			r.GetAll()
		}(i)
	}
	wg.Wait()
}

// --- Global accessor tests ---

func TestGlobalRegistryAccessors(t *testing.T) {
	if ListenerRegistry() == nil {
		t.Error("ListenerRegistry() returned nil")
	}
	if HandlerRegistry() == nil {
		t.Error("HandlerRegistry() returned nil")
	}
	if DialerRegistry() == nil {
		t.Error("DialerRegistry() returned nil")
	}
	if ConnectorRegistry() == nil {
		t.Error("ConnectorRegistry() returned nil")
	}
	if ServiceRegistry() == nil {
		t.Error("ServiceRegistry() returned nil")
	}
	if ChainRegistry() == nil {
		t.Error("ChainRegistry() returned nil")
	}
	if HopRegistry() == nil {
		t.Error("HopRegistry() returned nil")
	}
	if AutherRegistry() == nil {
		t.Error("AutherRegistry() returned nil")
	}
	if AdmissionRegistry() == nil {
		t.Error("AdmissionRegistry() returned nil")
	}
	if BypassRegistry() == nil {
		t.Error("BypassRegistry() returned nil")
	}
	if ResolverRegistry() == nil {
		t.Error("ResolverRegistry() returned nil")
	}
	if HostsRegistry() == nil {
		t.Error("HostsRegistry() returned nil")
	}
	if RecorderRegistry() == nil {
		t.Error("RecorderRegistry() returned nil")
	}
	if TrafficLimiterRegistry() == nil {
		t.Error("TrafficLimiterRegistry() returned nil")
	}
	if ConnLimiterRegistry() == nil {
		t.Error("ConnLimiterRegistry() returned nil")
	}
	if RateLimiterRegistry() == nil {
		t.Error("RateLimiterRegistry() returned nil")
	}
	if IngressRegistry() == nil {
		t.Error("IngressRegistry() returned nil")
	}
	if RouterRegistry() == nil {
		t.Error("RouterRegistry() returned nil")
	}
	if SDRegistry() == nil {
		t.Error("SDRegistry() returned nil")
	}
	if ObserverRegistry() == nil {
		t.Error("ObserverRegistry() returned nil")
	}
	if LoggerRegistry() == nil {
		t.Error("LoggerRegistry() returned nil")
	}
}

// Verify each accessor returns the same instance on repeated calls.
func TestGlobalRegistrySingleton(t *testing.T) {
	if ListenerRegistry() != ListenerRegistry() {
		t.Error("ListenerRegistry not singleton")
	}
	if HandlerRegistry() != HandlerRegistry() {
		t.Error("HandlerRegistry not singleton")
	}
	if DialerRegistry() != DialerRegistry() {
		t.Error("DialerRegistry not singleton")
	}
	if ConnectorRegistry() != ConnectorRegistry() {
		t.Error("ConnectorRegistry not singleton")
	}
	if ServiceRegistry() != ServiceRegistry() {
		t.Error("ServiceRegistry not singleton")
	}
	if ChainRegistry() != ChainRegistry() {
		t.Error("ChainRegistry not singleton")
	}
	if HopRegistry() != HopRegistry() {
		t.Error("HopRegistry not singleton")
	}
	if AutherRegistry() != AutherRegistry() {
		t.Error("AutherRegistry not singleton")
	}
	if AdmissionRegistry() != AdmissionRegistry() {
		t.Error("AdmissionRegistry not singleton")
	}
	if BypassRegistry() != BypassRegistry() {
		t.Error("BypassRegistry not singleton")
	}
	if ResolverRegistry() != ResolverRegistry() {
		t.Error("ResolverRegistry not singleton")
	}
	if HostsRegistry() != HostsRegistry() {
		t.Error("HostsRegistry not singleton")
	}
	if RecorderRegistry() != RecorderRegistry() {
		t.Error("RecorderRegistry not singleton")
	}
	if TrafficLimiterRegistry() != TrafficLimiterRegistry() {
		t.Error("TrafficLimiterRegistry not singleton")
	}
	if ConnLimiterRegistry() != ConnLimiterRegistry() {
		t.Error("ConnLimiterRegistry not singleton")
	}
	if RateLimiterRegistry() != RateLimiterRegistry() {
		t.Error("RateLimiterRegistry not singleton")
	}
	if IngressRegistry() != IngressRegistry() {
		t.Error("IngressRegistry not singleton")
	}
	if RouterRegistry() != RouterRegistry() {
		t.Error("RouterRegistry not singleton")
	}
	if SDRegistry() != SDRegistry() {
		t.Error("SDRegistry not singleton")
	}
	if ObserverRegistry() != ObserverRegistry() {
		t.Error("ObserverRegistry not singleton")
	}
	if LoggerRegistry() != LoggerRegistry() {
		t.Error("LoggerRegistry not singleton")
	}
}

// --- Admission wrapper tests ---

type mockAdmission struct {
	admit bool
}

func (m *mockAdmission) Admit(_ context.Context, _, _ string, _ ...admission.Option) bool {
	return m.admit
}

func TestAdmissionRegistry_GetEmpty(t *testing.T) {
	r := new(admissionRegistry)
	if v := r.Get(""); v != nil {
		t.Fatal("Get(empty) should return nil")
	}
}

func TestAdmissionRegistry_Delegate(t *testing.T) {
	r := new(admissionRegistry)
	mock := &mockAdmission{admit: true}
	r.Register("test", mock)

	w := r.Get("test")
	if w == nil {
		t.Fatal("Get returned nil")
	}
	if !w.Admit(context.Background(), "tcp", "1.2.3.4") {
		t.Fatal("Admit should delegate to mock")
	}
}

func TestAdmissionRegistry_HotReload(t *testing.T) {
	r := new(admissionRegistry)
	r.Register("h", &mockAdmission{admit: false})

	w := r.Get("h")
	if w.Admit(context.Background(), "tcp", "x") {
		t.Fatal("expected false from first mock")
	}

	// Hot-reload: replace the underlying value.
	r.Register("h", &mockAdmission{admit: true}) // will fail with ErrDup
	r.Unregister("h")
	r.Register("h", &mockAdmission{admit: true})

	// Same wrapper should now see the new value.
	if !w.Admit(context.Background(), "tcp", "x") {
		t.Fatal("wrapper did not pick up re-registered value")
	}
}

func TestAdmissionRegistry_NilUnderlying(t *testing.T) {
	r := new(admissionRegistry)
	r.Register("missing", &mockAdmission{})
	r.Unregister("missing")

	w := r.Get("missing")
	if w == nil {
		t.Fatal("Get should return wrapper even if underlying is nil")
	}
	// Should not panic, should return false.
	if w.Admit(context.Background(), "tcp", "x") {
		t.Fatal("nil underlying should return false")
	}
}

// --- Auther wrapper tests ---

type mockAuther struct {
	id    string
	valid bool
}

func (m *mockAuther) Authenticate(_ context.Context, _, _ string, _ ...auth.Option) (string, bool) {
	return m.id, m.valid
}

func TestAutherRegistry_GetEmpty(t *testing.T) {
	r := new(autherRegistry)
	if v := r.Get(""); v != nil {
		t.Fatal("Get(empty) should return nil")
	}
}

func TestAutherRegistry_Delegate(t *testing.T) {
	r := new(autherRegistry)
	r.Register("a", &mockAuther{id: "user1", valid: true})

	w := r.Get("a")
	id, ok := w.Authenticate(context.Background(), "user", "pass")
	if !ok || id != "user1" {
		t.Fatalf("Authenticate = (%q, %v), want (user1, true)", id, ok)
	}
}

func TestAutherRegistry_NilUnderlying(t *testing.T) {
	r := new(autherRegistry)
	w := r.Get("ghost")
	// No underlying value registered → should return ("", true) per wrapper default.
	id, ok := w.Authenticate(context.Background(), "u", "p")
	if !ok || id != "" {
		t.Fatalf("nil underlying = (%q, %v), want (\"\", true)", id, ok)
	}
}

// --- Bypass wrapper tests ---

type mockBypass struct {
	contains   bool
	whitelist bool
}

func (m *mockBypass) Contains(_ context.Context, _, _ string, _ ...bypass.Option) bool {
	return m.contains
}

func (m *mockBypass) IsWhitelist() bool { return m.whitelist }

func TestBypassRegistry_Delegate(t *testing.T) {
	r := new(bypassRegistry)
	r.Register("b", &mockBypass{contains: true, whitelist: true})

	w := r.Get("b")
	if !w.Contains(context.Background(), "tcp", "1.2.3.4") {
		t.Fatal("Contains should delegate")
	}
	if !w.IsWhitelist() {
		t.Fatal("IsWhitelist should delegate")
	}
}

func TestBypassRegistry_NilUnderlying(t *testing.T) {
	r := new(bypassRegistry)
	w := r.Get("ghost")
	if w.Contains(context.Background(), "tcp", "x") {
		t.Fatal("nil underlying Contains should return false")
	}
	if w.IsWhitelist() {
		t.Fatal("nil underlying IsWhitelist should return false")
	}
}

// --- Chain wrapper tests ---

type mockChainer struct {
	route chain.Route
	md    metadata.Metadata
}

func (m *mockChainer) Route(_ context.Context, _, _ string, _ ...chain.RouteOption) chain.Route {
	return m.route
}
func (m *mockChainer) Marker() selector.Marker {
	return nil
}
func (m *mockChainer) Metadata() metadata.Metadata { return m.md }

func TestChainRegistry_Delegate(t *testing.T) {
	r := new(chainRegistry)
	r.Register("c", &mockChainer{})

	w := r.Get("c")
	if w == nil {
		t.Fatal("Get returned nil")
	}
	if w.Route(context.Background(), "tcp", "addr") != nil {
		t.Fatal("mock returns nil route")
	}
}

func TestChainRegistry_NilUnderlying(t *testing.T) {
	r := new(chainRegistry)
	w := r.Get("ghost")
	if w.Route(context.Background(), "tcp", "x") != nil {
		t.Fatal("nil underlying Route should return nil")
	}
}

// --- Hop wrapper tests ---

type mockHop struct {
	node  *chain.Node
	nodes []*chain.Node
}

func (m *mockHop) Select(_ context.Context, _ ...hop.SelectOption) *chain.Node {
	return m.node
}
func (m *mockHop) Nodes() []*chain.Node { return m.nodes }

func TestHopRegistry_Delegate(t *testing.T) {
	r := new(hopRegistry)
	r.Register("h", &mockHop{})

	w := r.Get("h")
	if w.Select(context.Background()) != nil {
		t.Fatal("mock Select returns nil")
	}
}

func TestHopRegistry_NilUnderlying(t *testing.T) {
	r := new(hopRegistry)
	w := r.Get("ghost")
	if w.Select(context.Background()) != nil {
		t.Fatal("nil underlying Select should return nil")
	}
}

// TestHopRegistry_NodeListDelegate confirms the wrapper returned by Get
// satisfies hop.NodeList and forwards Nodes() to the underlying hop. The
// forwarder sniffer relies on this to compute body-size before selection for
// named hops; without delegation, body matching silently never triggers.
func TestHopRegistry_NodeListDelegate(t *testing.T) {
	n1 := chain.NewNode("n1", "example.com:80")
	n2 := chain.NewNode("n2", "example.com:81",
		chain.MatcherBodySizeNodeOption(65536),
	)
	r := new(hopRegistry)
	r.Register("h", &mockHop{nodes: []*chain.Node{n1, n2}})

	w := r.Get("h")
	nl, ok := w.(hop.NodeList)
	if !ok {
		t.Fatal("registry wrapper must satisfy hop.NodeList")
	}
	nodes := nl.Nodes()
	if len(nodes) != 2 {
		t.Fatalf("Nodes() returned %d nodes, want 2", len(nodes))
	}
	// Verify node options are visible through the wrapper (body-size aggregation
	// depends on reading MatcherBodySize off the exposed nodes).
	if got := nodes[1].Options().MatcherBodySize; got != 65536 {
		t.Errorf("MatcherBodySize through wrapper = %d, want 65536", got)
	}
}

// --- Hosts wrapper tests ---

type mockHosts struct {
	ips []net.IP
	ok  bool
}

func (m *mockHosts) Lookup(_ context.Context, _, _ string, _ ...hosts.Option) ([]net.IP, bool) {
	return m.ips, m.ok
}

func TestHostsRegistry_Delegate(t *testing.T) {
	r := new(hostsRegistry)
	ips := []net.IP{net.ParseIP("1.2.3.4")}
	r.Register("h", &mockHosts{ips: ips, ok: true})

	w := r.Get("h")
	result, ok := w.Lookup(context.Background(), "tcp", "example.com")
	if !ok || len(result) != 1 {
		t.Fatalf("Lookup = (%v, %v)", result, ok)
	}
}

func TestHostsRegistry_NilUnderlying(t *testing.T) {
	r := new(hostsRegistry)
	w := r.Get("ghost")
	ips, ok := w.Lookup(context.Background(), "tcp", "x")
	if ok || ips != nil {
		t.Fatal("nil underlying should return (nil, false)")
	}
}

// --- Ingress wrapper tests ---

type mockIngress struct {
	rule *ingress.Rule
	set  bool
}

func (m *mockIngress) GetRule(_ context.Context, _ string, _ ...ingress.Option) *ingress.Rule {
	return m.rule
}
func (m *mockIngress) SetRule(_ context.Context, _ *ingress.Rule, _ ...ingress.Option) bool {
	return m.set
}

func TestIngressRegistry_Delegate(t *testing.T) {
	r := new(ingressRegistry)
	r.Register("i", &mockIngress{set: true})

	w := r.Get("i")
	if w.GetRule(context.Background(), "example.com") != nil {
		t.Fatal("mock GetRule returns nil")
	}
	if !w.SetRule(context.Background(), nil) {
		t.Fatal("SetRule should delegate")
	}
}

func TestIngressRegistry_NilUnderlying(t *testing.T) {
	r := new(ingressRegistry)
	w := r.Get("ghost")
	if w.GetRule(context.Background(), "x") != nil {
		t.Fatal("nil GetRule should return nil")
	}
	if w.SetRule(context.Background(), nil) {
		t.Fatal("nil SetRule should return false")
	}
}

// --- TrafficLimiter wrapper tests ---

type mockTrafficLimiter struct {
	in  traffic.Limiter
	out traffic.Limiter
}

func (m *mockTrafficLimiter) In(_ context.Context, _ string, _ ...limiter.Option) traffic.Limiter {
	return m.in
}
func (m *mockTrafficLimiter) Out(_ context.Context, _ string, _ ...limiter.Option) traffic.Limiter {
	return m.out
}

func TestTrafficLimiterRegistry_Delegate(t *testing.T) {
	r := new(trafficLimiterRegistry)
	r.Register("tl", &mockTrafficLimiter{})

	w := r.Get("tl")
	if w.In(context.Background(), "k") != nil {
		t.Fatal("mock In returns nil")
	}
	if w.Out(context.Background(), "k") != nil {
		t.Fatal("mock Out returns nil")
	}
}

func TestTrafficLimiterRegistry_NilUnderlying(t *testing.T) {
	r := new(trafficLimiterRegistry)
	w := r.Get("ghost")
	if w.In(context.Background(), "k") != nil {
		t.Fatal("nil In should return nil")
	}
	if w.Out(context.Background(), "k") != nil {
		t.Fatal("nil Out should return nil")
	}
}

// --- ConnLimiter wrapper tests ---

type mockConnLimiter struct {
	lim conn.Limiter
}

func (m *mockConnLimiter) Limiter(_ string) conn.Limiter { return m.lim }

func TestConnLimiterRegistry_Delegate(t *testing.T) {
	r := new(connLimiterRegistry)
	r.Register("cl", &mockConnLimiter{})

	w := r.Get("cl")
	if w.Limiter("k") != nil {
		t.Fatal("mock returns nil limiter")
	}
}

func TestConnLimiterRegistry_NilUnderlying(t *testing.T) {
	r := new(connLimiterRegistry)
	w := r.Get("ghost")
	if w.Limiter("k") != nil {
		t.Fatal("nil underlying should return nil")
	}
}

// --- RateLimiter wrapper tests ---

type mockRateLimiter struct {
	lim rate.Limiter
}

func (m *mockRateLimiter) Limiter(_ string) rate.Limiter { return m.lim }

func TestRateLimiterRegistry_Delegate(t *testing.T) {
	r := new(rateLimiterRegistry)
	r.Register("rl", &mockRateLimiter{})

	w := r.Get("rl")
	if w.Limiter("k") != nil {
		t.Fatal("mock returns nil limiter")
	}
}

func TestRateLimiterRegistry_NilUnderlying(t *testing.T) {
	r := new(rateLimiterRegistry)
	w := r.Get("ghost")
	if w.Limiter("k") != nil {
		t.Fatal("nil underlying should return nil")
	}
}

// --- Observer wrapper tests ---

type mockObserver struct {
	err error
}

func (m *mockObserver) Observe(_ context.Context, _ []observer.Event, _ ...observer.Option) error {
	return m.err
}

func TestObserverRegistry_Delegate(t *testing.T) {
	r := new(observerRegistry)
	r.Register("o", &mockObserver{})

	w := r.Get("o")
	if err := w.Observe(context.Background(), nil); err != nil {
		t.Fatalf("Observe = %v", err)
	}
}

func TestObserverRegistry_NilUnderlying(t *testing.T) {
	r := new(observerRegistry)
	w := r.Get("ghost")
	if err := w.Observe(context.Background(), nil); err != nil {
		t.Fatal("nil underlying Observe should return nil")
	}
}

type mockCloseableObserver struct {
	closed bool
}

func (m *mockCloseableObserver) Observe(_ context.Context, _ []observer.Event, _ ...observer.Option) error {
	return nil
}
func (m *mockCloseableObserver) Close() error {
	m.closed = true
	return nil
}

func TestObserverRegistry_WrapperClose(t *testing.T) {
	r := new(observerRegistry)
	mock := &mockCloseableObserver{}
	r.Register("o", mock)

	w := r.Get("o")
	if err := w.(interface{ Close() error }).Close(); err != nil {
		t.Fatal(err)
	}
	if !mock.closed {
		t.Fatal("wrapper Close did not close underlying")
	}
}

func TestObserverRegistry_WrapperCloseNilUnderlying(t *testing.T) {
	r := new(observerRegistry)
	w := r.Get("ghost")
	if err := w.(interface{ Close() error }).Close(); err != nil {
		t.Fatalf("Close on nil underlying: %v", err)
	}
}

// --- Recorder wrapper tests ---

type mockRecorder struct {
	err error
}

func (m *mockRecorder) Record(_ context.Context, _ []byte, _ ...recorder.RecordOption) error {
	return m.err
}

func TestRecorderRegistry_Delegate(t *testing.T) {
	r := new(recorderRegistry)
	r.Register("r", &mockRecorder{})

	w := r.Get("r")
	if err := w.Record(context.Background(), []byte("data")); err != nil {
		t.Fatalf("Record = %v", err)
	}
}

func TestRecorderRegistry_NilUnderlying(t *testing.T) {
	r := new(recorderRegistry)
	w := r.Get("ghost")
	if err := w.Record(context.Background(), []byte("x")); err != nil {
		t.Fatal("nil underlying Record should return nil")
	}
}

// --- Resolver wrapper tests ---

type mockResolver struct {
	ips []net.IP
	err error
}

func (m *mockResolver) Resolve(_ context.Context, _, _ string, _ ...resolver.Option) ([]net.IP, error) {
	return m.ips, m.err
}

func TestResolverRegistry_Delegate(t *testing.T) {
	r := new(resolverRegistry)
	ips := []net.IP{net.ParseIP("1.2.3.4")}
	r.Register("r", &mockResolver{ips: ips})

	w := r.Get("r")
	result, err := w.Resolve(context.Background(), "tcp", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("Resolve = %v", result)
	}
}

func TestResolverRegistry_NilUnderlying(t *testing.T) {
	r := new(resolverRegistry)
	w := r.Get("ghost")
	ips, err := w.Resolve(context.Background(), "tcp", "x")
	if !errors.Is(err, resolver.ErrInvalid) {
		t.Fatalf("expected resolver.ErrInvalid, got %v", err)
	}
	if ips != nil {
		t.Fatal("should return nil IPs")
	}
}

// --- Router wrapper tests ---

type mockRouter struct {
	route *router.Route
}

func (m *mockRouter) GetRoute(_ context.Context, _ string, _ ...router.Option) *router.Route {
	return m.route
}

func TestRouterRegistry_Delegate(t *testing.T) {
	r := new(routerRegistry)
	r.Register("r", &mockRouter{})

	w := r.Get("r")
	if w.GetRoute(context.Background(), "1.2.3.4") != nil {
		t.Fatal("mock returns nil route")
	}
}

func TestRouterRegistry_NilUnderlying(t *testing.T) {
	r := new(routerRegistry)
	w := r.Get("ghost")
	if w.GetRoute(context.Background(), "x") != nil {
		t.Fatal("nil underlying should return nil")
	}
}

// --- SD wrapper tests ---

type mockSD struct {
	services []*sd.Service
	err      error
}

func (m *mockSD) Register(_ context.Context, _ *sd.Service, _ ...sd.Option) error {
	return m.err
}
func (m *mockSD) Deregister(_ context.Context, _ *sd.Service) error { return m.err }
func (m *mockSD) Renew(_ context.Context, _ *sd.Service) error      { return m.err }
func (m *mockSD) Get(_ context.Context, _ string) ([]*sd.Service, error) {
	return m.services, m.err
}

func TestSDRegistry_Delegate(t *testing.T) {
	r := new(sdRegistry)
	svcs := []*sd.Service{{Name: "test"}}
	r.Register("s", &mockSD{services: svcs})

	w := r.Get("s")
	if err := w.Register(context.Background(), &sd.Service{Name: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Deregister(context.Background(), &sd.Service{}); err != nil {
		t.Fatal(err)
	}
	if err := w.Renew(context.Background(), &sd.Service{}); err != nil {
		t.Fatal(err)
	}
	result, err := w.Get(context.Background(), "test")
	if err != nil || len(result) != 1 {
		t.Fatalf("Get = (%v, %v)", result, err)
	}
}

func TestSDRegistry_NilUnderlying(t *testing.T) {
	r := new(sdRegistry)
	w := r.Get("ghost")
	if err := w.Register(context.Background(), nil); err != nil {
		t.Fatal("nil Register should return nil")
	}
	if err := w.Deregister(context.Background(), nil); err != nil {
		t.Fatal("nil Deregister should return nil")
	}
	if err := w.Renew(context.Background(), nil); err != nil {
		t.Fatal("nil Renew should return nil")
	}
	if svcs, err := w.Get(context.Background(), "x"); err != nil || svcs != nil {
		t.Fatalf("nil Get = (%v, %v)", svcs, err)
	}
}

// --- Logger registry tests ---

type mockLogger struct{}

func (m *mockLogger) Trace(_ ...any)                              {}
func (m *mockLogger) Tracef(_ string, _ ...any)                   {}
func (m *mockLogger) Debug(_ ...any)                              {}
func (m *mockLogger) Debugf(_ string, _ ...any)                   {}
func (m *mockLogger) Info(_ ...any)                               {}
func (m *mockLogger) Infof(_ string, _ ...any)                    {}
func (m *mockLogger) Warn(_ ...any)                               {}
func (m *mockLogger) Warnf(_ string, _ ...any)                    {}
func (m *mockLogger) Error(_ ...any)                              {}
func (m *mockLogger) Errorf(_ string, _ ...any)                   {}
func (m *mockLogger) Fatal(_ ...any)                              {}
func (m *mockLogger) Fatalf(_ string, _ ...any)                   {}
func (m *mockLogger) GetLevel() logger.LogLevel                   { return logger.DebugLevel }
func (m *mockLogger) IsLevelEnabled(_ logger.LogLevel) bool       { return true }
func (m *mockLogger) WithFields(_ map[string]any) logger.Logger   { return m }

func TestLoggerRegistry_RegisterGet(t *testing.T) {
	r := new(loggerRegistry)
	l := &mockLogger{}
	r.Register("log", l)
	if v := r.Get("log"); v == nil {
		t.Fatal("Get returned nil")
	}
}

func TestLoggerRegistry_GetEmpty(t *testing.T) {
	r := new(loggerRegistry)
	if v := r.Get(""); v != nil {
		t.Fatal("empty name should return nil logger")
	}
}

// --- Service registry tests ---

func TestServiceRegistry_RegisterGet(t *testing.T) {
	r := new(serviceRegistry)
	svc := &closeableService{}
	r.Register("svc", svc)
	if v := r.Get("svc"); v == nil {
		t.Fatal("Get returned nil")
	}
}

// --- Factory registry tests (listener, handler, dialer, connector) ---
// These call logger.Fatal on duplicate, so we only test the non-duplicate path.

func TestListenerRegistry_Register(t *testing.T) {
	r := new(listenerRegistry)
	factory := func(_ ...listener.Option) listener.Listener { return nil }
	if err := r.Register("tcp", factory); err != nil {
		t.Fatal(err)
	}
	if !r.IsRegistered("tcp") {
		t.Fatal("should be registered")
	}
}

func TestHandlerRegistry_Register(t *testing.T) {
	r := new(handlerRegistry)
	factory := func(_ ...handler.Option) handler.Handler { return nil }
	if err := r.Register("http", factory); err != nil {
		t.Fatal(err)
	}
	if !r.IsRegistered("http") {
		t.Fatal("should be registered")
	}
}

func TestDialerRegistry_Register(t *testing.T) {
	r := new(dialerRegistry)
	factory := func(_ ...dialer.Option) dialer.Dialer { return nil }
	if err := r.Register("tcp", factory); err != nil {
		t.Fatal(err)
	}
	if !r.IsRegistered("tcp") {
		t.Fatal("should be registered")
	}
}

func TestConnectorRegistry_Register(t *testing.T) {
	r := new(connectorRegistry)
	factory := func(_ ...connector.Option) connector.Connector { return nil }
	if err := r.Register("http", factory); err != nil {
		t.Fatal(err)
	}
	if !r.IsRegistered("http") {
		t.Fatal("should be registered")
	}
}

// --- Interface satisfaction checks ---

var _ reg.Registry[NewListener] = (*listenerRegistry)(nil)
var _ reg.Registry[NewHandler] = (*handlerRegistry)(nil)
var _ reg.Registry[NewDialer] = (*dialerRegistry)(nil)
var _ reg.Registry[NewConnector] = (*connectorRegistry)(nil)
var _ reg.Registry[service.Service] = (*serviceRegistry)(nil)
var _ reg.Registry[chain.Chainer] = (*chainRegistry)(nil)
var _ reg.Registry[hop.Hop] = (*hopRegistry)(nil)
var _ reg.Registry[auth.Authenticator] = (*autherRegistry)(nil)
var _ reg.Registry[admission.Admission] = (*admissionRegistry)(nil)
var _ reg.Registry[bypass.Bypass] = (*bypassRegistry)(nil)
var _ reg.Registry[resolver.Resolver] = (*resolverRegistry)(nil)
var _ reg.Registry[hosts.HostMapper] = (*hostsRegistry)(nil)
var _ reg.Registry[recorder.Recorder] = (*recorderRegistry)(nil)
var _ reg.Registry[traffic.TrafficLimiter] = (*trafficLimiterRegistry)(nil)
var _ reg.Registry[conn.ConnLimiter] = (*connLimiterRegistry)(nil)
var _ reg.Registry[rate.RateLimiter] = (*rateLimiterRegistry)(nil)
var _ reg.Registry[ingress.Ingress] = (*ingressRegistry)(nil)
var _ reg.Registry[router.Router] = (*routerRegistry)(nil)
var _ reg.Registry[sd.SD] = (*sdRegistry)(nil)
var _ reg.Registry[observer.Observer] = (*observerRegistry)(nil)
var _ reg.Registry[logger.Logger] = (*loggerRegistry)(nil)

