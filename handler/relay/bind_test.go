package relay

import (
	"context"
	"testing"
	"time"

	"github.com/go-gost/core/handler"
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