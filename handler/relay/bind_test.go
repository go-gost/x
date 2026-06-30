package relay

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/resolver"
	"github.com/go-gost/relay"
)

// handleBind tests use a real TCP listener on port 0 to verify the bind flow.
// The Handle method is called with a CmdBind request, and the response is
// checked for StatusOK + an AddrFeature.

func TestHandleBind_Disabled(t *testing.T) {
	rh := newInitdHandler(t,
		handler.LoggerOption(&testLogger{}),
	)
	// bind is disabled by default

	fc := &fakeConn{buf: buildRelayBindRequest(t, "127.0.0.1:0", "")}
	err := rh.Handle(context.Background(), fc)
	// handleBind returns the error from resp.WriteTo(conn) — when the write
	// succeeds the returned error is nil. The response status indicates the
	// denial, not the returned error.
	_ = err

	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusForbidden {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusForbidden)
	}
}

func TestHandleBind_TCP(t *testing.T) {
	rh := &relayHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	rh.parseMetadata(testMD(map[string]any{"bind": true}))

	fc := &fakeConn{buf: buildRelayBindRequest(t, "127.0.0.1:0", "")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- rh.Handle(ctx, fc)
	}()

	// Wait for the response (bindTCP writes the response before blocking on Serve)
	// bindTCP calls resp.WriteTo(conn) then upgrades to mux session.
	// Since the fakeConn doesn't support mux (it's not a real mux-compatible conn),
	// the mux.ClientSession call will fail.
	// But we should at least get the response before that.
	select {
	case err := <-errCh:
		if err != nil {
			// bindTCP will fail when mux.ClientSession tries to upgrade the fakeConn
			// That's expected — the response was written before that
			_ = err
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for bind handler")
	}

	// Check the response — should have StatusOK and an AddrFeature
	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusOK {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusOK)
	}

	// Verify response has at least one feature
	if len(resp.Features) == 0 {
		t.Error("response has no features, expected AddrFeature")
	}
}

func TestHandleBind_UDP(t *testing.T) {
	rh := &relayHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	rh.parseMetadata(testMD(map[string]any{"bind": true}))

	fc := &fakeConn{buf: buildRelayBindRequest(t, "127.0.0.1:0", "udp")}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- rh.Handle(ctx, fc)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			_ = err
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for bind handler")
	}

	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusOK {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// resolvePacketConn tests
// ---------------------------------------------------------------------------

type testPacketConn struct {
	net.PacketConn
	lastAddr net.Addr
	lastData []byte
}

func (c *testPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.lastAddr = addr
	c.lastData = make([]byte, len(b))
	copy(c.lastData, b)
	return len(b), nil
}

type stubResolver struct {
	ips []net.IP
	err error
}

func (r *stubResolver) Resolve(ctx context.Context, network, host string, opts ...resolver.Option) ([]net.IP, error) {
	return r.ips, r.err
}

type stubHostMapper struct{}

func (m *stubHostMapper) Lookup(ctx context.Context, network, host string, opts ...hosts.Option) ([]net.IP, bool) {
	return nil, false
}

type testDomainAddr struct{}

func (a *testDomainAddr) Network() string { return "udp" }
func (a *testDomainAddr) String() string  { return "dns.google:53" }

func Test_resolvePacketConn_domain(t *testing.T) {
	r := &resolvePacketConn{
		PacketConn: &testPacketConn{},
		resolver:   &stubResolver{ips: []net.IP{net.ParseIP("1.2.3.4")}},
		hostMapper: &stubHostMapper{},
	}

	_, err := r.WriteTo([]byte("data"), &testDomainAddr{})
	if err != nil {
		t.Fatal(err)
	}

	tpc := r.PacketConn.(*testPacketConn)
	udpAddr, ok := tpc.lastAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", tpc.lastAddr)
	}
	if !udpAddr.IP.Equal(net.ParseIP("1.2.3.4")) || udpAddr.Port != 53 {
		t.Fatalf("expected 1.2.3.4:53, got %v", udpAddr)
	}
}

func Test_resolvePacketConn_ipPassthrough(t *testing.T) {
	r := &resolvePacketConn{
		PacketConn: &testPacketConn{},
		resolver:   &stubResolver{err: errors.New("should not be called")},
		hostMapper: &stubHostMapper{},
	}

	ipAddr := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
	_, err := r.WriteTo([]byte("data"), ipAddr)
	if err != nil {
		t.Fatal(err)
	}

	tpc := r.PacketConn.(*testPacketConn)
	udpAddr, ok := tpc.lastAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", tpc.lastAddr)
	}
	if !udpAddr.IP.Equal(net.ParseIP("8.8.8.8")) || udpAddr.Port != 53 {
		t.Fatalf("expected 8.8.8.8:53, got %v", udpAddr)
	}
}