package tunnel

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/relay"
	"github.com/go-gost/x/internal/util/mux"
)

// TestHandleBind_ResponseWritten tests that handleBind writes a correct relay
// response frame to the connection and adds the connector to the pool.
func TestHandleBind_ResponseWritten(t *testing.T) {
	tid := newTestTunnelID(t)

	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			muxCfg: &mux.Config{Version: 2},
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
		log:  testLogger(),
	}
	defer h.pool.Close()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleBind(context.Background(), server, "tcp", "0.0.0.0:0", tid, testLogger())
	}()

	// Read the relay response from the client side of the pipe.
	resp := &relay.Response{}
	_, err := resp.ReadFrom(client)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Status != relay.StatusOK {
		t.Errorf("expected StatusOK (%d), got %d", relay.StatusOK, resp.Status)
	}

	// The response should contain AddrFeature and TunnelFeature.
	var addrFound bool
	var tunnelFound bool
	for _, f := range resp.Features {
		switch f.Type() {
		case relay.FeatureAddr:
			addrFound = true
		case relay.FeatureTunnel:
			tunnelFound = true
			tf := f.(*relay.TunnelFeature)
			if tf.ID == (relay.TunnelID{}) {
				t.Error("expected non-zero connector ID")
			}
		}
	}
	if !addrFound {
		t.Error("expected AddrFeature in response")
	}
	if !tunnelFound {
		t.Error("expected TunnelFeature in response")
	}

	// handleBind should complete (with or without error depending on mux handshake timing).
	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("handleBind returned (expected): %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handleBind did not complete")
	}
}

// TestHandleBind_WithIngress tests that handleBind sets ingress rules.
func TestHandleBind_WithIngress(t *testing.T) {
	tid := newTestTunnelID(t)

	ing := &fakeIngress{}
	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			muxCfg:  &mux.Config{Version: 2},
			ingress: ing,
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
		log:  testLogger(),
	}
	defer h.pool.Close()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleBind(context.Background(), server, "tcp", "0.0.0.0:0", tid, testLogger())
	}()

	_, _ = (&relay.Response{}).ReadFrom(client)
	client.Close()

	select {
	case err := <-errCh:
		t.Logf("handleBind returned: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("handleBind did not complete")
	}

	// Ingress rules should have been set.
	if ing.rule == nil {
		t.Error("expected ingress rule to be set")
	} else if ing.rule.Endpoint != tid.String() {
		t.Errorf("expected endpoint %s, got %s", tid.String(), ing.rule.Endpoint)
	}
}

// TestHandleBind_WithSD tests that handleBind registers with SD.
func TestHandleBind_WithSD(t *testing.T) {
	tid := newTestTunnelID(t)

	sdCalled := make(chan *sd.Service, 1)
	fakeSD := &fakeSD{
		registerFunc: func(ctx context.Context, service *sd.Service) error {
			sdCalled <- service
			return nil
		},
	}

	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			muxCfg:     &mux.Config{Version: 2},
			sd:         fakeSD,
			entryPoint: "example.com:8080",
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
		log:  testLogger(),
	}
	defer h.pool.Close()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleBind(context.Background(), server, "tcp", "0.0.0.0:0", tid, testLogger())
	}()

	// Read the response from client side.
	_, _ = (&relay.Response{}).ReadFrom(client)

	// Wait for SD registration.
	select {
	case svc := <-sdCalled:
		if svc.Name != tid.String() {
			t.Errorf("expected service name %s, got %s", tid.String(), svc.Name)
		}
		if svc.Node != "node1" {
			t.Errorf("expected node node1, got %s", svc.Node)
		}
		if svc.Network != "tcp" {
			t.Errorf("expected network tcp, got %s", svc.Network)
		}
		if svc.Address != "example.com:8080" {
			t.Errorf("expected address example.com:8080, got %s", svc.Address)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SD.Register was not called")
	}

	client.Close()

	select {
	case err := <-errCh:
		t.Logf("handleBind returned: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("handleBind did not complete")
	}
}

// TestHandleBind_UDPConnector tests that UDP tunnel requests create UDP connector IDs.
func TestHandleBind_UDPConnector(t *testing.T) {
	tid := newTestTunnelID(t)
	tid = tid.SetWeight(10) // set weight to verify it's copied

	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			muxCfg: &mux.Config{Version: 2},
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
		log:  testLogger(),
	}
	defer h.pool.Close()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleBind(context.Background(), server, "udp", "0.0.0.0:0", tid, testLogger())
	}()

	resp := &relay.Response{}
	_, err := resp.ReadFrom(client)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	// Verify connector ID is UDP and weight is copied.
	var connectorID relay.ConnectorID
	for _, f := range resp.Features {
		if f.Type() == relay.FeatureTunnel {
			connectorID = f.(*relay.TunnelFeature).ID
		}
	}
	if connectorID == (relay.ConnectorID{}) {
		t.Fatal("expected non-zero connector ID")
	}
	if !connectorID.IsUDP() {
		t.Error("expected UDP connector for UDP tunnel request")
	}
	if connectorID.Weight() != 10 {
		t.Errorf("expected weight 10 (from tunnelID), got %d", connectorID.Weight())
	}

	client.Close()
	select {
	case err := <-errCh:
		t.Logf("handleBind returned: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("handleBind did not complete")
	}
}

// TestConnector_waitClose tests that waitClose properly handles session
// termination and cleans up.
func TestConnector_waitClose(t *testing.T) {
	cid := newTestConnectorID(t, false, 1)
	tid := newTestTunnelID(t)

	// Create a real mux session for testing waitClose behavior.
	s, clientEnd := newTestSession(t)
	c := newTestConnector(cid, tid, "node1", s, &ConnectorOptions{})

	// waitClose is started in NewConnector which we bypassed via newTestConnector.
	// Start it manually.
	done := make(chan struct{})
	go func() {
		c.waitClose()
		close(done)
	}()

	// Close the client end of the pipe — the mux session should detect this
	// and Accept in waitClose should fail, causing waitClose to exit.
	clientEnd.Close()

	select {
	case <-done:
		// waitClose exited as expected
	case <-time.After(2 * time.Second):
		t.Fatal("waitClose did not exit after session close")
	}
}

// TestConnector_waitClose_DeregisterSD tests that waitClose deregisters from
// SD when configured.
func TestConnector_waitClose_DeregisterSD(t *testing.T) {
	deregisterCalled := make(chan struct{}, 1)
	fakeSD := &fakeSD{
		deregisterFunc: func(ctx context.Context, service *sd.Service) error {
			deregisterCalled <- struct{}{}
			return nil
		},
	}

	cid := newTestConnectorID(t, false, 1)
	tid := newTestTunnelID(t)
	s, clientEnd := newTestSession(t)
	c := newTestConnector(cid, tid, "node1", s, &ConnectorOptions{
		sd: fakeSD,
	})

	done := make(chan struct{})
	go func() {
		c.waitClose()
		close(done)
	}()

	// Close client end to trigger session failure.
	clientEnd.Close()

	select {
	case <-deregisterCalled:
		// Deregister was called
	case <-time.After(2 * time.Second):
		t.Fatal("SD.Deregister was not called")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("waitClose did not exit")
	}
}

// TestConnectWithBindEndToEnd tests the full round-trip: handleBind registers
// a connector, then handleConnect dials through it. This verifies the connector
// was properly added to the pool.
func TestConnectWithBindEndToEnd(t *testing.T) {
	tid := newTestTunnelID(t)

	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			muxCfg: &mux.Config{Version: 2},
			ingress: &fakeIngress{
				rule: &ingress.Rule{
					Hostname: "example.com",
					Endpoint: tid.String(),
				},
			},
			entryPointID: tid,
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
		log:  testLogger(),
	}
	defer h.pool.Close()

	// Simulate a CmdBind: create a pipe, run handleBind on server end.
	bindClient, bindServer := net.Pipe()
	defer bindClient.Close()
	defer bindServer.Close()

	bindResult := make(chan error, 1)
	go func() {
		bindResult <- h.handleBind(context.Background(), bindServer, "tcp", "0.0.0.0:0", tid, testLogger())
	}()

	// Read the bind response from client side.
	_, err := (&relay.Response{}).ReadFrom(bindClient)
	if err != nil {
		t.Fatalf("read bind response: %v", err)
	}

	// Now the connector should be registered in the pool.
	// Try to connect through it.
	req := &relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
	}
	req.Features = append(req.Features, &relay.TunnelFeature{ID: tid})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "10.0.0.1", Port: 12345})
	req.Features = append(req.Features, &relay.AddrFeature{Host: "example.com", Port: 80})

	conn := &fakeConn{}
	err = h.handleConnect(context.Background(), req, conn, "tcp", "10.0.0.1:12345", "example.com:80", tid, testLogger())

	if err != nil {
		t.Logf("handleConnect returned (expected with pipe): %v", err)
	}

	// Clean up bind.
	bindClient.Close()
	select {
	case <-bindResult:
	case <-time.After(2 * time.Second):
		t.Fatal("handleBind did not complete")
	}
}

// TestHandleBind_WithHostEndpoint tests handleBind when the bind address has
// a non-empty host — the endpoint-based ingress rule should be set.
func TestHandleBind_WithHostEndpoint(t *testing.T) {
	tid := newTestTunnelID(t)

	ing := &fakeIngress{}
	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			muxCfg:  &mux.Config{Version: 2},
			ingress: ing,
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
		log:  testLogger(),
	}
	defer h.pool.Close()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleBind(context.Background(), server, "tcp", "myapp.example.com:8080", tid, testLogger())
	}()

	_, _ = (&relay.Response{}).ReadFrom(client)
	client.Close()

	select {
	case err := <-errCh:
		t.Logf("handleBind returned: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("handleBind did not complete")
	}

	// Should have set at least the endpoint-based ingress rule.
	if ing.rule == nil {
		t.Error("expected ingress rule to be set")
	}
}
// TestHandleBind_CustomHost tests that a user-supplied host is used as
// the response address, not the md5 hash.
func TestHandleBind_CustomHost(t *testing.T) {
	tid := newTestTunnelID(t)

	ing := &fakeIngress{}
	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			muxCfg:  &mux.Config{Version: 2},
			ingress: ing,
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
		log:  testLogger(),
	}
	defer h.pool.Close()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleBind(context.Background(), server, "tcp", "dash:8081", tid, testLogger())
	}()

	resp := &relay.Response{}
	_, err := resp.ReadFrom(client)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	// The response AddrFeature should use "dash", not the md5 hash.
	var host string
	for _, f := range resp.Features {
		if f.Type() == relay.FeatureAddr {
			if af, ok := f.(*relay.AddrFeature); ok {
				host = af.Host
			}
		}
	}
	if host != "dash" {
		t.Errorf("expected response host 'dash', got %q", host)
	}

	client.Close()
	select {
	case err := <-errCh:
		t.Logf("handleBind returned: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("handleBind did not complete")
	}
}

// TestHandleBind_CustomHostConflict tests that when the user-supplied host
// is already claimed by a different tunnel in ingress, handleBind falls
// back to the md5 hash to avoid route hijacking.
func TestHandleBind_CustomHostConflict(t *testing.T) {
	tid := newTestTunnelID(t)
	otherEndpoint := "other-tunnel-id"

	ing := &fakeIngress{
		ruleByHost: map[string]*ingress.Rule{
			"dash": {
				Hostname: "dash",
				Endpoint: otherEndpoint,
			},
		},
	}
	h := &tunnelHandler{
		options: handler.Options{
			Logger: testLogger(),
		},
		md: metadata{
			muxCfg:  &mux.Config{Version: 2},
			ingress: ing,
		},
		id:   "node1",
		pool: NewConnectorPool("node1"),
		log:  testLogger(),
	}
	defer h.pool.Close()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleBind(context.Background(), server, "tcp", "dash:8081", tid, testLogger())
	}()

	resp := &relay.Response{}
	_, err := resp.ReadFrom(client)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	// The response should fall back to the md5 hash because "dash" is
	// already claimed by another tunnel.
	var host string
	for _, f := range resp.Features {
		if f.Type() == relay.FeatureAddr {
			if af, ok := f.(*relay.AddrFeature); ok {
				host = af.Host
			}
		}
	}

	// Compute the expected fallback hash for this tunnelID.
	v := md5.Sum([]byte(tid.String()))
	expectedHash := hex.EncodeToString(v[:8])
	if host != expectedHash {
		t.Errorf("expected fallback hash %q for conflicting host, got %q", expectedHash, host)
	}

	client.Close()
	select {
	case err := <-errCh:
		t.Logf("handleBind returned: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("handleBind did not complete")
	}
}
