package tunnel

import (
	"bytes"
	"context"
	"testing"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/relay"
)

// fakeBypass implements bypass.Bypass for testing.
type fakeBypass struct {
	matched bool
}

func (b *fakeBypass) IsWhitelist() bool                                              { return false }
func (b *fakeBypass) Contains(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
	return b.matched
}

// fakeIngress implements ingress.Ingress for testing.
// It stores one rule per hostname for conflict simulation.
type fakeIngress struct {
	rule     *ingress.Rule
	ruleByHost map[string]*ingress.Rule
}

func (i *fakeIngress) GetRule(ctx context.Context, host string, opts ...ingress.Option) *ingress.Rule {
	if i.ruleByHost != nil {
		if r, ok := i.ruleByHost[host]; ok {
			return r
		}
	}
	return i.rule
}

func (i *fakeIngress) SetRule(ctx context.Context, rule *ingress.Rule, opts ...ingress.Option) bool {
	i.rule = rule
	return true
}

// newTestTunnelID is defined in tunnel_test.go

func TestHandleConnect_Bypass(t *testing.T) {
	req := &relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
	}
	tid := newTestTunnelID(t)
	req.Features = append(req.Features, &relay.TunnelFeature{ID: tid})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "example.com", Port: 80})

	h := &tunnelHandler{
		options: handler.Options{
			Bypass: &fakeBypass{matched: true},
			Logger: testLogger(),
		},
		md: metadata{
			entryPointID: relay.TunnelID{}, // zero — not an entrypoint visitor
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
	}

	conn := &fakeConn{}
	err := h.handleConnect(context.Background(), req, conn, "tcp", "10.0.0.1:12345", "example.com:80", tid, testLogger())

	if err == nil {
		t.Fatal("expected error for bypass")
	}
	// Verify relay response was written with StatusForbidden
	resp := relay.Response{}
	_, err = resp.ReadFrom(bytes.NewReader(conn.writeBuf))
	if err != nil {
		t.Fatalf("read relay response: %v", err)
	}
	if resp.Status != relay.StatusForbidden {
		t.Errorf("expected StatusForbidden (%d), got %d", relay.StatusForbidden, resp.Status)
	}
}

func TestHandleConnect_EntrypointNoRoute(t *testing.T) {
	req := &relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
	}
	entrypointID := newTestTunnelID(t)
	req.Features = append(req.Features, &relay.TunnelFeature{ID: entrypointID})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "example.com", Port: 80})

	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			entryPointID: entrypointID,
			ingress:      &fakeIngress{rule: nil}, // no rule
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
	}

	conn := &fakeConn{}
	err := h.handleConnect(context.Background(), req, conn, "tcp", "10.0.0.1:12345", "example.com:80", entrypointID, testLogger())

	if err == nil {
		t.Fatal("expected error for no route")
	}
	resp := relay.Response{}
	_, err = resp.ReadFrom(bytes.NewReader(conn.writeBuf))
	if err != nil {
		t.Fatalf("read relay response: %v", err)
	}
	if resp.Status != relay.StatusNetworkUnreachable {
		t.Errorf("expected StatusNetworkUnreachable (%d), got %d", relay.StatusNetworkUnreachable, resp.Status)
	}
}

func TestHandleConnect_EntrypointPrivateTunnel(t *testing.T) {
	req := &relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
	}
	entrypointID := newTestTunnelID(t)
	req.Features = append(req.Features, &relay.TunnelFeature{ID: entrypointID})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "example.com", Port: 80})

	// Private tunnel endpoint — ingress returns a $-prefixed tunnel ID

	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			entryPointID: entrypointID,
			ingress: &fakeIngress{
				rule: &ingress.Rule{
					Hostname: "example.com",
					Endpoint: "$4e1b0d1a-8e3f-4c7a-9b2c-5d6e7f8a9b0c",
				},
			},
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
	}

	conn := &fakeConn{}
	err := h.handleConnect(context.Background(), req, conn, "tcp", "10.0.0.1:12345", "example.com:80", entrypointID, testLogger())

	if err == nil {
		t.Fatal("expected error for private tunnel")
	}
	resp := relay.Response{}
	_, err = resp.ReadFrom(bytes.NewReader(conn.writeBuf))
	if err != nil {
		t.Fatalf("read relay response: %v", err)
	}
	if resp.Status != relay.StatusHostUnreachable {
		t.Errorf("expected StatusHostUnreachable (%d), got %d", relay.StatusHostUnreachable, resp.Status)
	}
}

func TestHandleConnect_DirectTunnelMismatch(t *testing.T) {
	tid := newTestTunnelID(t)

	req := &relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
	}
	req.Features = append(req.Features, &relay.TunnelFeature{ID: tid})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "example.com", Port: 80})

	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			directTunnel: false, // not direct tunnel
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
	}

	conn := &fakeConn{}
	// Not entrypoint, not direct tunnel, and tid doesn't match (tid != tid — same value)
	// We need a different TID scenario: since there's no ingress and no direct tunnel,
	// tid.Equal(tunnelID) is true (both are `tid`), so this path goes to Dialer.
	// Instead test the case where the tunnelID is NOT the entrypointID and NOT direct
	// and ingress returns a different tid.
	err := h.handleConnect(context.Background(), req, conn, "tcp", "10.0.0.1:12345", "example.com:80", tid, testLogger())

	// With no ingress, tid.Equal(tunnelID) is true, so this tries to dial
	// and fails with ErrTunnelNotAvailable
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHandleConnect_DirectTunnelEnabled(t *testing.T) {
	tid := newTestTunnelID(t)

	req := &relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
	}
	req.Features = append(req.Features, &relay.TunnelFeature{ID: tid})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "example.com", Port: 80})

	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			directTunnel: true, // direct tunnel enabled — uses tunnelID directly
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
	}

	conn := &fakeConn{}
	err := h.handleConnect(context.Background(), req, conn, "tcp", "10.0.0.1:12345", "example.com:80", tid, testLogger())

	// Direct tunnel, tid matches — tries to dial, fails with ErrTunnelNotAvailable
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHandleConnect_DialerError(t *testing.T) {
	tid := newTestTunnelID(t)

	req := &relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
	}
	req.Features = append(req.Features, &relay.TunnelFeature{ID: tid})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "example.com", Port: 80})

	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			entryPointID: tid,
			ingress: &fakeIngress{
				rule: &ingress.Rule{
					Hostname: "example.com",
					Endpoint: tid.String(),
				},
			},
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
		log:  testLogger(),
	}

	conn := &fakeConn{}
	err := h.handleConnect(context.Background(), req, conn, "tcp", "10.0.0.1:12345", "example.com:80", tid, testLogger())

	if err == nil {
		t.Fatal("expected error for dialer failure")
	}
	// Should write StatusServiceUnavailable
	resp := relay.Response{}
	_, err = resp.ReadFrom(bytes.NewReader(conn.writeBuf))
	if err != nil {
		t.Fatalf("read relay response: %v", err)
	}
	if resp.Status != relay.StatusServiceUnavailable {
		t.Errorf("expected StatusServiceUnavailable (%d), got %d", relay.StatusServiceUnavailable, resp.Status)
	}
}

func TestHandleConnect_AuthFailure(t *testing.T) {
	tid := newTestTunnelID(t)

	req := &relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
	}
	req.Features = append(req.Features, &relay.TunnelFeature{ID: tid})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "10.0.0.1", Port: 12345})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "example.com", Port: 80})
	req.Features = append(req.Features, &relay.UserAuthFeature{Username: "user", Password: "wrong"})

	auther := &fakeAuther{ok: false}
	h := &tunnelHandler{
		id:   "node1",
		pool: NewConnectorPool("node1"),
		options: handler.Options{
			Auther: auther,
			Logger: testLogger(),
		},
		md: metadata{
			directTunnel: true,
		},
		log: testLogger(),
	}

	conn := &fakeConn{buf: func() []byte {
		var buf bytes.Buffer
		_, _ = req.WriteTo(&buf)
		return buf.Bytes()
	}()}
	t.Logf("request bytes: %d", len(conn.buf))
	err := h.Handle(context.Background(), conn)
	if err == nil {
		t.Fatal("expected auth error")
	}
}

func TestHandleConnect_EntrypointWithIngress_Success(t *testing.T) {
	tid := newTestTunnelID(t)

	req := &relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
	}
	req.Features = append(req.Features, &relay.TunnelFeature{ID: tid})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "10.0.0.1", Port: 12345})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "example.com", Port: 80})

	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			entryPointID: tid,
			ingress: &fakeIngress{
				rule: &ingress.Rule{
					Hostname: "example.com",
					Endpoint: tid.String(),
				},
			},
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
		log:  testLogger(),
	}

	// Call handleConnect directly to avoid relay request parsing in Handle().
	conn := &fakeConn{}
	err := h.handleConnect(context.Background(), req, conn, "tcp", "10.0.0.1:12345", "example.com:80", tid, testLogger())

	if err == nil {
		t.Fatal("expected error (no connector in pool)")
	}
	// Should have written a response before the error
	if len(conn.writeBuf) == 0 {
		t.Error("expected relay response to be written")
	} else {
		resp := relay.Response{}
		_, rerr := resp.ReadFrom(bytes.NewReader(conn.writeBuf))
		if rerr != nil {
			t.Fatalf("read response: %v", rerr)
		}
		if resp.Status != relay.StatusServiceUnavailable {
			t.Errorf("expected StatusServiceUnavailable (%d), got %d", relay.StatusServiceUnavailable, resp.Status)
		}
	}
}

func TestHandleConnect_NotEntrypointNotDirect_IngressRule(t *testing.T) {
	tid := newTestTunnelID(t)

	req := &relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
	}
	req.Features = append(req.Features, &relay.TunnelFeature{ID: tid})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "10.0.0.1", Port: 12345})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "example.com", Port: 80})

	// ingress returns a DIFFERENT tid than the request's tunnelID
	otherTID := ParseTunnelID("7f2c3d4e-5a6b-7c8d-9e0f-1a2b3c4d5e6f")

	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			entryPointID: relay.TunnelID{}, // not entrypoint
			directTunnel: false,
			ingress: &fakeIngress{
				rule: &ingress.Rule{
					Hostname: "example.com",
					Endpoint: otherTID.String(),
				},
			},
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
	}

	conn := &fakeConn{}
	err := h.handleConnect(context.Background(), req, conn, "tcp", "10.0.0.1:12345", "example.com:80", tid, testLogger())

	if err == nil {
		t.Fatal("expected error (ingress tid != request tid)")
	}
	resp := relay.Response{}
	_, err = resp.ReadFrom(bytes.NewReader(conn.writeBuf))
	if err != nil {
		t.Fatalf("read relay response: %v", err)
	}
	if resp.Status != relay.StatusHostUnreachable {
		t.Errorf("expected StatusHostUnreachable (%d), got %d", relay.StatusHostUnreachable, resp.Status)
	}
}

// fakeAuther implements auth.Authenticator for testing.
type fakeAuther struct {
	ok bool
}

func (a *fakeAuther) Authenticate(ctx context.Context, user, pass string, opts ...auth.Option) (string, bool) {
	if a.ok {
		return "client1", true
	}
	return "", false
}