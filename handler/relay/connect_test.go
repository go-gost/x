package relay

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/relay"
	xrecorder "github.com/go-gost/x/recorder"
)

func newConnectHandler(t *testing.T, opts ...handler.Option) *relayHandler {
	t.Helper()
	// Default: provide a working router
	defaultOpts := []handler.Option{
		handler.LoggerOption(&testLogger{}),
		handler.RouterOption(&mockRouter{
			dialFn: func(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
				pr, pw := net.Pipe()
				pw.Close()
				return pr, nil
			},
		}),
	}
	return newInitdHandler(t, append(defaultOpts, opts...)...)
}

func TestHandleConnect_TCP(t *testing.T) {
	rh := newConnectHandler(t)
	rh.md.noDelay = true

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	// Should get a StatusOK response
	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusOK {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusOK)
	}
}

func TestHandleConnect_UDP(t *testing.T) {
	rh := newConnectHandler(t)
	rh.md.noDelay = true

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:53", "udp")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusOK {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusOK)
	}
}

func TestHandleConnect_NoDelay(t *testing.T) {
	rh := newConnectHandler(t)
	// Override noDelay to true
	rh.md.noDelay = true

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	// Response should be written before pipe
	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusOK {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusOK)
	}
}

func TestHandleConnect_RouterDialFails(t *testing.T) {
	rh := newInitdHandler(t,
		handler.RouterOption(&mockRouter{
			dialFn: func(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
				return nil, net.UnknownNetworkError("mock failure")
			},
		}),
	)

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err == nil {
		t.Fatal("expected error")
	}

	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusNetworkUnreachable {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusNetworkUnreachable)
	}
}

func TestHandleConnect_Bypass(t *testing.T) {
	mb := &mockBypass{
		containsFn: func(ctx context.Context, network, addr string, opts ...bypass.Option) bool {
			return true
		},
	}
	rh := newInitdHandler(t,
		handler.BypassOption(mb),
		handler.RouterOption(&mockRouter{}),
	)

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err == nil {
		t.Fatal("expected error")
	}

	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusForbidden {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusForbidden)
	}
}

func TestHandleConnect_HashHost(t *testing.T) {
	rh := newConnectHandler(t)
	rh.md.hash = "host"

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
}

func TestHandleConnect_SniffingDisabled(t *testing.T) {
	rh := newConnectHandler(t)
	rh.md.noDelay = true
	// sniffing is false by default — verify no sniffing activity
	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	resp := readRelayResponse(t, fc.writeBuf.Bytes())
	if resp.Status != relay.StatusOK {
		t.Errorf("Status = %d, want %d", resp.Status, relay.StatusOK)
	}
}

func TestHandleConnect_Unix(t *testing.T) {
	rh := newInitdHandler(t,
		handler.LoggerOption(&testLogger{}),
		handler.RouterOption(&mockRouter{}),
	)

	// Build a connect request with unix network
	req := relay.Request{Version: relay.Version1, Cmd: relay.CmdConnect}
	af := &relay.AddrFeature{Host: "/tmp/test.sock", Port: 0}
	req.Features = append(req.Features, af)
	req.Features = append(req.Features, &relay.NetworkFeature{Network: relay.NetworkUnix})
	var buf bytes.Buffer
	req.WriteTo(&buf)

	fc := &fakeConn{buf: buf.Bytes()}
	err := rh.Handle(context.Background(), fc)
	// unix connect to /tmp/test.sock will fail, but it should reach the dial step
	if err == nil {
		t.Fatal("expected error for unix dial to /tmp/test.sock")
	}
}

func TestHandleConnect_Serial(t *testing.T) {
	rh := newInitdHandler(t,
		handler.LoggerOption(&testLogger{}),
		handler.RouterOption(&mockRouter{}),
	)

	// Build a connect request with serial network
	req := relay.Request{Version: relay.Version1, Cmd: relay.CmdConnect}
	af := &relay.AddrFeature{Host: "/invalid/serial", Port: 0}
	req.Features = append(req.Features, af)
	req.Features = append(req.Features, &relay.NetworkFeature{Network: relay.NetworkSerial})
	var buf bytes.Buffer
	req.WriteTo(&buf)

	fc := &fakeConn{buf: buf.Bytes()}
	err := rh.Handle(context.Background(), fc)
	if err == nil {
		t.Fatal("expected error for serial connect")
	}
}

func TestHandleConnect_WithObserver(t *testing.T) {
	obs := &fakeObserver{eventsCh: make(chan []observer.Event, 10)}
	rh := newConnectHandler(t,
		handler.ObserverOption(obs),
		handler.ServiceOption("test-svc"),
	)
	// Init creates the stats — but with a new Init
	// need to re-init with observer set
	// Actually newConnectHandler uses newInitdHandler which sets up observer...

	// The observer was set in handler options, so Init creates h.stats
	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
}

func TestHandleConnect_ReadTimeout(t *testing.T) {
	rh := &relayHandler{
		options: handler.Options{Logger: &testLogger{}},
	}
	rh.parseMetadata(testMD(map[string]any{"readTimeout": "50ms"}))

	fc := &fakeConn{} // empty buf — will block on read
	err := rh.Handle(context.Background(), fc)
	if err == nil {
		t.Error("expected error from read timeout")
	}
}

func TestHandleConnect_WithRecorder(t *testing.T) {
	rec := recorder.RecorderObject{
		Record:   xrecorder.RecorderServiceHandler,
		Recorder: &dummyRecorder{},
	}
	rh := newConnectHandler(t,
		handler.RecordersOption(rec),
	)

	fc := &fakeConn{buf: buildRelayConnectRequest(t, "example.com:80", "")}
	err := rh.Handle(context.Background(), fc)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
}