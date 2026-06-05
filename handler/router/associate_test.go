package router

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/router"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	"github.com/go-gost/x/internal/util/cache"
)

// ---------------------------------------------------------------------------
// handleAssociate tests
// ---------------------------------------------------------------------------

func TestHandleAssociate_NoIngress(t *testing.T) {
	h := newInitdHandler(t)
	h.md.ingress = nil

	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	reqData := buildRelayAssociateRequest(t, "10.0.0.1:0", rid, "ip")

	conn := &fakeConn{buf: reqData}
	err := h.handleAssociate(context.Background(), conn, "ip", "10.0.0.1", rid, &testLogger{})
	// handleAssociate returns io.EOF when the packet read loop exhausts the
	// fake connection's data — that signals normal completion, not a failure.
	// packetConn.Read uses io.ReadFull, which returns io.ErrUnexpectedEOF
	// when the underlying connection has been exhausted mid-frame, rather
	// than the plain io.EOF that the loop checks for.
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("handleAssociate: %v", err)
	}

	// Response should contain StatusOK.
	resp := readRelayResponse(t, conn.writeBuf.Bytes())
	if resp.Status != relay.StatusOK {
		t.Errorf("status = %d, want StatusOK", resp.Status)
	}
}

func TestHandleAssociate_IngressMatch(t *testing.T) {
	h := newInitdHandler(t)
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))

	// The ingress endpoint UUID must parse to the same bytes as the routerID.
	// routerID bytes: 0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66
	h.md.ingress = &mockIngress{
		getRuleFn: func(ctx context.Context, host string, opts ...ingress.Option) *ingress.Rule {
			return &ingress.Rule{
				Hostname: "10.0.0.1",
				Endpoint: "30313233-3435-3637-3839-616263646566",
			}
		},
	}

	reqData := buildRelayAssociateRequest(t, "10.0.0.1:0", rid, "ip")
	conn := &fakeConn{buf: reqData}
	err := h.handleAssociate(context.Background(), conn, "ip", "10.0.0.1", rid, &testLogger{})
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("handleAssociate: %v", err)
	}

	resp := readRelayResponse(t, conn.writeBuf.Bytes())
	if resp.Status != relay.StatusOK {
		t.Errorf("status = %d, want StatusOK", resp.Status)
	}
}

func TestHandleAssociate_IngressMismatch(t *testing.T) {
	h := newInitdHandler(t)
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))

	// Ingress rule points to a DIFFERENT router ID.
	h.md.ingress = &mockIngress{
		getRuleFn: func(ctx context.Context, host string, opts ...ingress.Option) *ingress.Rule {
			return &ingress.Rule{
				Hostname: "10.0.0.1",
				Endpoint: "ffffffff-ffff-ffff-ffff-ffffffffffff",
			}
		},
	}

	reqData := buildRelayAssociateRequest(t, "10.0.0.1:0", rid, "ip")
	conn := &fakeConn{buf: reqData}
	err := h.handleAssociate(context.Background(), conn, "ip", "10.0.0.1", rid, &testLogger{})
	if err == nil {
		t.Fatal("expected error for ingress mismatch")
	}

	// Should have written StatusHostUnreachable.
	resp := readRelayResponse(t, conn.writeBuf.Bytes())
	if resp.Status != relay.StatusHostUnreachable {
		t.Errorf("status = %d, want HostUnreachable", resp.Status)
	}
}

// ---------------------------------------------------------------------------
// handlePacket tests
// ---------------------------------------------------------------------------

func TestHandlePacket_IPv4_ConnectorForward(t *testing.T) {
	var buf bytes.Buffer
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	cid := relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa"))
	c := NewConnector(rid, cid, "10.0.0.1", &buf, nil)

	h := newInitdHandler(t)
	h.pool.Add(rid, c)
	h.md.routerCacheEnabled = false

	// Provide a fallback router so getRoute returns a route whose gateway
	// matches the connector's host.
	h.md.router = &mockRouter{
		getRouteFn: func(ctx context.Context, dst string, opts ...router.Option) *router.Route {
			return &router.Route{
				Dst:     "10.0.0.0/24",
				Gateway: "10.0.0.1",
			}
		},
	}

	pkt := buildIPv4Packet("10.0.0.2", "10.0.0.1", []byte("hello"))
	err := h.handlePacket(context.Background(), pkt, rid, &testLogger{})
	if err != nil {
		t.Fatalf("handlePacket: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("no data written to connector")
	}
}

func TestHandlePacket_IPv6_ConnectorForward(t *testing.T) {
	var buf bytes.Buffer
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	cid := relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa"))
	c := NewConnector(rid, cid, "2001:db8::1", &buf, nil)

	h := newInitdHandler(t)
	h.pool.Add(rid, c)
	h.md.routerCacheEnabled = false

	// Provide a fallback router so getRoute returns a route whose gateway
	// matches the connector's host.
	h.md.router = &mockRouter{
		getRouteFn: func(ctx context.Context, dst string, opts ...router.Option) *router.Route {
			return &router.Route{
				Dst:     "2001:db8::/32",
				Gateway: "2001:db8::1",
			}
		},
	}

	pkt := buildIPv6Packet("2001:db8::2", "2001:db8::1", []byte("hello"))
	err := h.handlePacket(context.Background(), pkt, rid, &testLogger{})
	if err != nil {
		t.Fatalf("handlePacket: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("no data written to connector")
	}
}

func TestHandlePacket_Unknown(t *testing.T) {
	h := newInitdHandler(t)
	err := h.handlePacket(context.Background(), []byte{0, 1, 2, 3}, relay.TunnelID{}, &testLogger{})
	if err == nil {
		t.Fatal("expected error for unknown packet type")
	}
}

func TestHandlePacket_NoRoute(t *testing.T) {
	h := newInitdHandler(t)
	h.md.routerCacheEnabled = false

	pkt := buildIPv4Packet("10.0.0.2", "192.168.1.1", []byte("data"))
	err := h.handlePacket(context.Background(), pkt, relay.NewTunnelID([]byte("0123456789abcdef")), &testLogger{})
	if err == nil {
		t.Fatal("expected error for no route")
	}
}

func TestHandlePacket_NoConnector_EntrypointFallback(t *testing.T) {
	// When no connector is found for the destination, handlePacket falls
	// through to getAddrforRoute and writes via epConn.
	h := newInitdHandler(t)
	h.md.routerCacheEnabled = false

	// Provide a fallback router so getRoute returns a route.
	h.md.router = &mockRouter{
		getRouteFn: func(ctx context.Context, dst string, opts ...router.Option) *router.Route {
			return &router.Route{
				Dst:     "10.0.0.0/24",
				Gateway: "10.0.0.254",
			}
		},
	}

	// Provide an SD so getAddrforRoute returns an address.
	h.md.sd = &mockSD{
		getFn: func(ctx context.Context, name string) ([]*sd.Service, error) {
			return []*sd.Service{
				{ID: "svc-1", Name: name, Node: "other-node", Network: "udp", Address: "10.0.0.99:8080"},
			}, nil
		},
	}

	// Create a real epConn so WriteTo succeeds.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	h.epConn = pc

	pkt := buildIPv4Packet("10.0.0.2", "10.0.0.100", []byte("via-ep"))
	err = h.handlePacket(context.Background(), pkt, relay.NewTunnelID([]byte("0123456789abcdef")), &testLogger{})
	if err != nil {
		t.Fatalf("handlePacket: %v", err)
	}
}

// ---------------------------------------------------------------------------
// getRoute tests
// ---------------------------------------------------------------------------

func TestGetRoute_CacheHit(t *testing.T) {
	h := newInitdHandler(t)
	h.md.routerCacheEnabled = true
	h.md.routerCacheExpiration = time.Minute
	h.routeCache.Set("10.0.0.1", cache.NewItem(&router.Route{
		Dst:     "10.0.0.0/24",
		Gateway: "10.0.0.254",
	}, time.Minute))

	route := h.getRoute(context.Background(), "test-rid", "10.0.0.1")
	if route == nil {
		t.Fatal("getRoute returned nil")
	}
	if route.Gateway != "10.0.0.254" {
		t.Errorf("gateway = %s, want 10.0.0.254", route.Gateway)
	}
}

func TestGetRoute_CacheDisabled(t *testing.T) {
	h := newInitdHandler(t)
	h.md.routerCacheEnabled = false

	// With cache disabled, getRoute always performs a lookup.
	// Since cache is disabled, a cached value should NOT be returned even if one exists.
	h.routeCache.Set("10.0.0.1", cache.NewItem(&router.Route{
		Dst:     "10.0.0.0/24",
		Gateway: "10.0.0.254",
	}, time.Minute))

	route := h.getRoute(context.Background(), "test-rid", "10.0.0.1")
	// With cache disabled, the cached route must NOT be returned.
	// Since there is no registry router registered for "test-rid" and no
	// fallback router, the result should be nil.
	if route != nil {
		t.Errorf("getRoute returned %+v, want nil (cache disabled, no fallback)", route)
	}
}

func TestGetRoute_FallbackRouter(t *testing.T) {
	h := newInitdHandler(t)
	h.md.routerCacheEnabled = false
	h.md.router = &mockRouter{
		getRouteFn: func(ctx context.Context, dst string, opts ...router.Option) *router.Route {
			return &router.Route{
				Dst:     "10.0.0.0/24",
				Gateway: "10.0.0.254",
			}
		},
	}

	route := h.getRoute(context.Background(), "nonexistent-rid", "10.0.0.1")
	if route == nil {
		t.Fatal("getRoute returned nil")
	}
	if route.Gateway != "10.0.0.254" {
		t.Errorf("gateway = %s, want 10.0.0.254", route.Gateway)
	}
}

// ---------------------------------------------------------------------------
// getAddrforRoute tests
// ---------------------------------------------------------------------------

func TestGetAddrforRoute_NilSD(t *testing.T) {
	h := newInitdHandler(t)
	h.md.sd = nil

	addr := h.getAddrforRoute(context.Background(), "rid", "gateway")
	if addr != nil {
		t.Errorf("getAddrforRoute = %v, want nil", addr)
	}
}

func TestGetAddrforRoute_CacheHit(t *testing.T) {
	h := newInitdHandler(t)
	h.md.sd = &mockSD{}
	h.md.sdCacheExpiration = time.Minute

	expectedAddr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 8080}
	h.sdCache.Set("gateway@rid", cache.NewItem(expectedAddr, time.Minute))

	addr := h.getAddrforRoute(context.Background(), "rid", "gateway")
	if addr == nil {
		t.Fatal("getAddrforRoute returned nil")
	}
	if addr.String() != expectedAddr.String() {
		t.Errorf("addr = %s, want %s", addr.String(), expectedAddr.String())
	}
}

func TestGetAddrforRoute_SDLookup(t *testing.T) {
	h := newInitdHandler(t)
	h.id = "self-node"
	h.md.sdCacheExpiration = time.Minute

	h.md.sd = &mockSD{
		getFn: func(ctx context.Context, name string) ([]*sd.Service, error) {
			return []*sd.Service{
				{ID: "conn-1", Name: name, Node: "self-node", Network: "udp", Address: "10.0.0.1:8080"},
				{ID: "conn-2", Name: name, Node: "other-node", Network: "udp", Address: "10.0.0.2:8080"},
			}, nil
		},
	}

	addr := h.getAddrforRoute(context.Background(), "rid", "gateway")
	if addr == nil {
		t.Fatal("getAddrforRoute returned nil")
	}
	// Should have skipped self-node and returned other-node.
	if addr.String() != "10.0.0.2:8080" {
		t.Errorf("addr = %s, want 10.0.0.2:8080", addr.String())
	}
}

// ---------------------------------------------------------------------------
// sdRenew tests
// ---------------------------------------------------------------------------

func TestSdRenew_Cancel(t *testing.T) {
	h := newInitdHandler(t)

	renewCalled := make(chan struct{}, 1)
	h.md.sd = &mockSD{
		renewFn: func(ctx context.Context, svc *sd.Service) error {
			renewCalled <- struct{}{}
			return nil
		},
	}
	h.md.sdRenewInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	go h.sdRenew(ctx, "client-id", "connector-id")

	// Let it tick once.
	select {
	case <-renewCalled:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Renew")
	}

	cancel()
}

func TestSdRenew_NormalTick(t *testing.T) {
	h := newInitdHandler(t)

	tickCh := make(chan struct{}, 10)
	h.md.sd = &mockSD{
		renewFn: func(ctx context.Context, svc *sd.Service) error {
			tickCh <- struct{}{}
			return nil
		},
	}
	h.md.sdRenewInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go h.sdRenew(ctx, "client-id", "connector-id")

	select {
	case <-tickCh:
	case <-time.After(time.Second):
		t.Error("Renew was never called")
	}
}