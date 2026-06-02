package entrypoint

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	xctx "github.com/go-gost/x/ctx"
	xstats "github.com/go-gost/x/observer/stats"
	xrecorder "github.com/go-gost/x/recorder"
)

// test helpers

type nopLogger struct {
	logger.Logger
}

func (nopLogger) Debugf(format string, args ...any) {}
func (nopLogger) Infof(format string, args ...any)  {}
func (nopLogger) Warnf(format string, args ...any)  {}
func (nopLogger) Errorf(format string, args ...any) {}
func (nopLogger) Tracef(format string, args ...any) {}
func (nopLogger) Debug(args ...any)                 {}
func (nopLogger) Info(args ...any)                  {}
func (nopLogger) Warn(args ...any)                  {}
func (nopLogger) Error(args ...any)                 {}
func (nopLogger) Trace(args ...any)                 {}
func (nopLogger) Fatal(args ...any)                 {}
func (nopLogger) Fatalf(format string, args ...any) {}
func (nopLogger) GetLevel() logger.LogLevel         { return logger.ErrorLevel }
func (nopLogger) IsLevelEnabled(level logger.LogLevel) bool { return false }
func (nopLogger) WithFields(fields map[string]any) logger.Logger { return nopLogger{} }

func testLogger() logger.Logger { return nopLogger{} }

// mockIngress implements ingress.Ingress with immediate rule lookup.
type mockIngress struct {
	rules map[string]*ingress.Rule
}

func newMockIngress(rules []*ingress.Rule) *mockIngress {
	m := &mockIngress{rules: make(map[string]*ingress.Rule)}
	for _, r := range rules {
		m.rules[r.Hostname] = r
	}
	return m
}

func (m *mockIngress) GetRule(ctx context.Context, host string, opts ...ingress.Option) *ingress.Rule {
	// Strip port like real ingress does
	if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
		host = h
	}
	return m.rules[host]
}

func (m *mockIngress) SetRule(ctx context.Context, rule *ingress.Rule, opts ...ingress.Option) bool {
	m.rules[rule.Hostname] = rule
	return true
}

func newTestConfig() *Config {
	return &Config{
		Node:        "test-node",
		Service:     "test-service",
		Logger:      testLogger(),
		Ingress:     newMockIngress(nil),
		ReadTimeout: 15 * time.Second,
	}
}

type fakeDialFn struct {
	conn net.Conn
	node string
	cid  string
	err  error
}

func (f *fakeDialFn) dial(ctx DialContext, network, tid string) (net.Conn, string, string, error) {
	if f.err != nil {
		return nil, "", "", f.err
	}
	if f.conn == nil {
		return nil, "", "", fmt.Errorf("no connection")
	}
	return f.conn, f.node, f.cid, nil
}

type fakeConn struct {
	net.Conn
	readBuf  []byte
	offset   int
	writeBuf bytes.Buffer
	closed   bool
}

func (c *fakeConn) Read(b []byte) (n int, err error) {
	if c.offset >= len(c.readBuf) {
		return 0, io.EOF
	}
	n = copy(b, c.readBuf[c.offset:])
	c.offset += n
	return
}

func (c *fakeConn) Write(b []byte) (n int, err error) {
	return c.writeBuf.Write(b)
}

func (c *fakeConn) Close() error {
	c.closed = true
	return nil
}

func (c *fakeConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}
}

func (c *fakeConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 8080}
}

func (c *fakeConn) SetReadDeadline(t time.Time) error {
	return nil
}

// pipeConn is a simple in-memory pipe to simulate bidirectional connections.
// It embeds readBuf for tests that need to inject data.
type pipeConn struct {
	readBuf  []byte
	offset   int
	reader   *io.PipeReader
	writer   *io.PipeWriter
	closed   bool
	remote   net.Addr
	local    net.Addr
}

func (c *pipeConn) Read(b []byte) (n int, err error) {
	if c.readBuf != nil && c.offset < len(c.readBuf) {
		n = copy(b, c.readBuf[c.offset:])
		c.offset += n
		return n, nil
	}
	if c.reader == nil {
		return 0, io.EOF
	}
	return c.reader.Read(b)
}

func (c *pipeConn) Write(b []byte) (n int, err error) {
	if c.writer == nil {
		return len(b), nil
	}
	return c.writer.Write(b)
}

func (c *pipeConn) Close() error {
	if !c.closed {
		c.closed = true
		if c.reader != nil {
			c.reader.Close()
		}
		if c.writer != nil {
			c.writer.Close()
		}
	}
	return nil
}

func (c *pipeConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}
}

func (c *pipeConn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 8080}
}

func (c *pipeConn) SetReadDeadline(t time.Time) error { return nil }
func (c *pipeConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *pipeConn) SetDeadline(t time.Time) error { return nil }

func newPipePair() (*pipeConn, *pipeConn) {
	pr1, pw1 := io.Pipe()
	pr2, pw2 := io.Pipe()
	a := &pipeConn{reader: pr1, writer: pw2}
	b := &pipeConn{reader: pr2, writer: pw1}
	return a, b
}

// buildRelayConnectRequest builds a relay connect request for the entrypoint's
// handleConnect path.
func buildRelayConnectRequest(t *testing.T, tid relay.TunnelID, src, dst string) []byte {
	t.Helper()
	req := relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
	}
	if src != "" {
		af := &relay.AddrFeature{}
		af.ParseFrom(src)
		req.Features = append(req.Features, af)
	}
	if dst != "" {
		af := &relay.AddrFeature{}
		af.ParseFrom(dst)
		req.Features = append(req.Features, af)
	}
	req.Features = append(req.Features, &relay.TunnelFeature{ID: tid})
	var buf bytes.Buffer
	_, err := req.WriteTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// --- Tests ---

// parseUUID tests

func TestParseUUID(t *testing.T) {
	t.Run("valid uuid", func(t *testing.T) {
		b, err := parseUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(b) != 16 {
			t.Errorf("expected 16 bytes, got %d", len(b))
		}
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := parseUUID("short")
		if err == nil {
			t.Error("expected error for short string")
		}
	})

	t.Run("missing hyphens", func(t *testing.T) {
		_, err := parseUUID("6ba7b8109dad11d180b400c04fd430c8")
		if err == nil {
			t.Error("expected error without hyphens")
		}
	})

	t.Run("non-hex character", func(t *testing.T) {
		_, err := parseUUID("6ba7b810-9dad-11d1-80b4-00c04fd430zz")
		if err == nil {
			t.Error("expected error for non-hex characters")
		}
	})

	t.Run("uppercase hex", func(t *testing.T) {
		b, err := parseUUID("6BA7B810-9DAD-11D1-80B4-00C04FD430C8")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(b) != 16 {
			t.Errorf("expected 16 bytes, got %d", len(b))
		}
	})
}

// parseTunnelID tests

func TestParseTunnelID(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		tid := parseTunnelID("")
		if !tid.IsZero() {
			t.Error("expected zero tunnel ID for empty string")
		}
	})

	t.Run("valid uuid", func(t *testing.T) {
		tid := parseTunnelID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
		if tid.IsZero() {
			t.Error("expected non-zero tunnel ID")
		}
	})

	t.Run("private tunnel ($ prefix)", func(t *testing.T) {
		tid := parseTunnelID("$6ba7b810-9dad-11d1-80b4-00c04fd430c8")
		if !tid.IsPrivate() {
			t.Error("expected private tunnel ID")
		}
	})

	t.Run("invalid uuid returns zero", func(t *testing.T) {
		tid := parseTunnelID("not-a-uuid-at-all")
		if !tid.IsZero() {
			t.Error("expected zero tunnel ID for invalid input")
		}
	})

	t.Run("invalid uuid with $ prefix", func(t *testing.T) {
		tid := parseTunnelID("$not-a-uuid-at-all")
		if !tid.IsZero() {
			t.Error("expected zero tunnel ID for invalid input")
		}
	})
}

// New tests

func TestNew(t *testing.T) {
	t.Run("creates entrypoint with transport", func(t *testing.T) {
		dialFn := func(ctx DialContext, network, tid string) (net.Conn, string, string, error) {
			return nil, "", "", nil
		}
		ep := New(newTestConfig(), dialFn)
		if ep == nil {
			t.Fatal("expected non-nil entrypoint")
		}
		if ep.transport == nil {
			t.Error("expected non-nil transport")
		}
		if ep.node != "test-node" {
			t.Errorf("expected node test-node, got %s", ep.node)
		}
	})
}

// Handle tests

func TestHandle_PeekError(t *testing.T) {
	dialFn := func(ctx DialContext, network, tid string) (net.Conn, string, string, error) {
		return nil, "", "", nil
	}
	ep := New(newTestConfig(), dialFn)

	// Empty connection should fail peek
	conn := &fakeConn{readBuf: []byte{}}
	err := ep.Handle(context.Background(), conn)
	if err == nil {
		t.Error("expected error from empty connection")
	}
}

func TestHandle_HTTP_Path(t *testing.T) {
	ing := newMockIngress([]*ingress.Rule{
			{Hostname: "example.com", Endpoint: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
		})
	cfg := newTestConfig()
	cfg.Ingress = ing

	client, server := newPipePair()
	dialFn := func(ctx DialContext, network, tid string) (net.Conn, string, string, error) {
		return client, "test-node", "cid1", nil
	}
	ep := New(cfg, dialFn)

	httpReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	conn := &fakeConn{readBuf: []byte(httpReq)}

	go func() {
		// Server side: read the relay StatusOK response with address features
		resp := relay.Response{}
		_, err := resp.ReadFrom(server)
		if err != nil {
			return
		}
		server.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
		server.Close()
	}()

	err := ep.Handle(context.Background(), conn)
	// Pipe will close when the server side closes; Handle may return nil or EOF
	t.Logf("Handle HTTP returned: %v", err)
}

func TestHandle_Relay_Path(t *testing.T) {
	dialFn := func(ctx DialContext, network, tid string) (net.Conn, string, string, error) {
		client, server := newPipePair()
		go func() {
			// Read the StatusOK on the mux-stream (reply from public node)
			resp := relay.Response{}
			resp.ReadFrom(server)
			server.Close()
		}()
		return client, "test-node", "cid1", nil
	}

	tid := relay.NewTunnelID(func() []byte {
		u, _ := parseUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
		return u
	}())

	ep := New(newTestConfig(), dialFn)

	relayData := buildRelayConnectRequest(t, tid, "10.0.0.1:12345", "192.168.1.1:80")
	conn := &fakeConn{readBuf: relayData}

	err := ep.Handle(context.Background(), conn)
	// Expected: relay path processes, pipes, then returns
	t.Logf("Handle relay path returned: %v", err)
}

func TestHandle_Relay_NoTunnelID(t *testing.T) {
	dialFn := func(ctx DialContext, network, tid string) (net.Conn, string, string, error) {
		return nil, "", "", nil
	}
	ep := New(newTestConfig(), dialFn)

	// Relay request without tunnel feature
	req := relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
		Features: []relay.Feature{
			&relay.AddrFeature{Host: "10.0.0.1", Port: 12345},
		},
	}
	var buf bytes.Buffer
	req.WriteTo(&buf)

	conn := &fakeConn{readBuf: buf.Bytes()}
	err := ep.Handle(context.Background(), conn)
	if err == nil {
		t.Error("expected error for missing tunnel ID")
	}
}

// dial tests

func TestDial_NoIngress(t *testing.T) {
	ep := New(newTestConfig(), nil)
	_, err := ep.dial(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Error("expected error for host not in ingress")
	}
	if !strings.Contains(err.Error(), "no route to host") {
		t.Errorf("expected 'no route to host', got %v", err)
	}
}

func TestDial_PrivateTunnel(t *testing.T) {
	ing := newMockIngress([]*ingress.Rule{
		{Hostname: "internal.example.com", Endpoint: "$6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
	})
	cfg := newTestConfig()
	cfg.Ingress = ing
	ep := New(cfg, nil)

	_, err := ep.dial(context.Background(), "tcp", "internal.example.com:80")
	if err == nil {
		t.Error("expected error for private tunnel")
	}
	if !strings.Contains(err.Error(), "private tunnel") {
		t.Errorf("expected 'private tunnel', got %v", err)
	}
}

func TestDial_NilDialFn(t *testing.T) {
	ing := newMockIngress([]*ingress.Rule{
			{Hostname: "example.com", Endpoint: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
		})
	cfg := newTestConfig()
	cfg.Ingress = ing
	ep := New(cfg, nil)

	_, err := ep.dial(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Error("expected error for nil dialFn")
	}
}

func TestDial_DialFnError(t *testing.T) {
	ing := newMockIngress([]*ingress.Rule{
			{Hostname: "example.com", Endpoint: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
		})
	cfg := newTestConfig()
	cfg.Ingress = ing
	ep := New(cfg, func(ctx DialContext, network, tid string) (net.Conn, string, string, error) {
		return nil, "", "", fmt.Errorf("dial failed")
	})

	_, err := ep.dial(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Error("expected error from dialFn")
	}
}

func TestDial_RemoteNode(t *testing.T) {
	ing := newMockIngress([]*ingress.Rule{
			{Hostname: "example.com", Endpoint: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
		})
	cfg := newTestConfig()
	cfg.Ingress = ing
	client, _ := net.Pipe()
	ep := New(cfg, func(ctx DialContext, network, tid string) (net.Conn, string, string, error) {
		return client, "remote-node", "cid1", nil
	})

	conn, err := ep.dial(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Error("expected non-nil connection")
	}
}

func TestDial_LocalNode(t *testing.T) {
	ing := newMockIngress([]*ingress.Rule{
			{Hostname: "example.com", Endpoint: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
		})
	cfg := newTestConfig()
	cfg.Ingress = ing
	client, server := net.Pipe()
	ep := New(cfg, func(ctx DialContext, network, tid string) (net.Conn, string, string, error) {
		return client, "test-node", "cid1", nil
	})

	// For local node, expect relay StatusOK + address features written to stream
	go func() {
		resp := relay.Response{}
		_, err := resp.ReadFrom(server)
		if err != nil {
			return
		}
		server.Close()
	}()

	// Create a context with a source address so the local-node path
	// doesn't fail on ParseFrom("")
	ctx := xctx.ContextWithSrcAddr(context.Background(), &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345})
	conn, err := ep.dial(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Error("expected non-nil connection")
	}
}

// handleConnect tests

func TestHandleConnect_DialFnError(t *testing.T) {
	dialFn := func(ctx DialContext, network, tid string) (net.Conn, string, string, error) {
		return nil, "", "", fmt.Errorf("dial error")
	}
	ep := New(newTestConfig(), dialFn)

	tid := relay.NewTunnelID(func() []byte {
		u, _ := parseUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
		return u
	}())

	conn := &fakeConn{readBuf: buildRelayConnectRequest(t, tid, "10.0.0.1:12345", "")}

	// Use handleConnect directly (not via Handle dispatch)
	err := ep.handleConnect(context.Background(), conn, &xrecorder.HandlerRecorderObject{}, testLogger())
	if err == nil {
		t.Error("expected error from dial failure")
	}
}

// handleHTTP tests

func TestHandleHTTP_BadRequest(t *testing.T) {
	ep := New(newTestConfig(), nil)

	// Bad HTTP data
	conn := &fakeConn{readBuf: []byte("NOT HTTP\r\n")}

	err := ep.handleHTTP(context.Background(), conn, &xrecorder.HandlerRecorderObject{}, testLogger())
	if err == nil {
		t.Error("expected error for bad HTTP request")
	}
}

func TestHTTPRoundTrip_LoopDetection(t *testing.T) {
	ep := New(newTestConfig(), nil)
	ep.node = "test-node"

	// Request with our own node in Gost-Forwarded-Node header
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Gost-Forwarded-Node", "test-node")

	rw := &pipeConn{}
	ro := &xrecorder.HandlerRecorderObject{
		HTTP: &xrecorder.HTTPRecorderObject{},
	}
	pStats := xstats.Stats{}

	err := ep.httpRoundTrip(context.Background(), rw, req, ro, &pStats, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ro.HTTP.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", ro.HTTP.StatusCode)
	}
}

func TestHTTPRoundTrip_NoRoute(t *testing.T) {
	dialFn := func(ctx DialContext, network, tid string) (net.Conn, string, string, error) {
		return nil, "", "", errNoRoute
	}
	ep := New(newTestConfig(), dialFn)

	req, _ := http.NewRequest("GET", "http://unknown.example.com/", nil)
	rw := &fakeConn{}
	ro := &xrecorder.HandlerRecorderObject{
		HTTP: &xrecorder.HTTPRecorderObject{},
	}
	pStats := xstats.Stats{}

	err := ep.httpRoundTrip(context.Background(), rw, req, ro, &pStats, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(&rw.writeBuf), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", resp.StatusCode)
	}
}

func TestUpgradeType(t *testing.T) {
	t.Run("no upgrade header", func(t *testing.T) {
		h := http.Header{}
		if upgradeType(h) != "" {
			t.Error("expected empty for no upgrade header")
		}
	})

	t.Run("has upgrade", func(t *testing.T) {
		h := http.Header{}
		h.Set("Connection", "Upgrade")
		h.Set("Upgrade", "websocket")
		if upgradeType(h) != "websocket" {
			t.Errorf("expected 'websocket', got '%s'", upgradeType(h))
		}
	})

	t.Run("upgrade with multiple connection tokens", func(t *testing.T) {
		h := http.Header{}
		h.Set("Connection", "keep-alive, Upgrade")
		h.Set("Upgrade", "websocket")
		if upgradeType(h) != "websocket" {
			t.Errorf("expected 'websocket', got '%s'", upgradeType(h))
		}
	})
}

func TestHandleUpgradeResponse_MismatchedUpgrade(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{},
		Body:       &pipeConn{},
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "h2c") // mismatch

	ep := New(newTestConfig(), nil)
	err := ep.handleUpgradeResponse(context.Background(), &pipeConn{}, req, res, &xrecorder.HandlerRecorderObject{}, testLogger())
	if err == nil {
		t.Error("expected error for mismatched upgrade protocol")
	}
}

func TestHandleUpgradeResponse_NonWritableBody(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("not writable")),
	}
	res.Header.Set("Connection", "Upgrade")
	res.Header.Set("Upgrade", "websocket")

	ep := New(newTestConfig(), nil)
	err := ep.handleUpgradeResponse(context.Background(), &pipeConn{}, req, res, &xrecorder.HandlerRecorderObject{}, testLogger())
	if err == nil {
		t.Error("expected error for non-writable body")
	}
}

// eplistener tests

func TestTCPListener_Init_Accept_Close(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	tcpLn := NewTCPListener(ln)
	addr := tcpLn.Addr()
	if addr == nil {
		t.Error("expected non-nil addr")
	}

	err = tcpLn.Init(nil)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = tcpLn.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

// entrypointHandler tests

func TestNewEntrypointHandler(t *testing.T) {
	ep := New(newTestConfig(), nil)
	h := NewHandler(ep)
	if h == nil {
		t.Fatal("expected non-nil handler")
	}

	err := h.Init(nil)
	if err != nil {
		t.Errorf("Init should return nil, got %v", err)
	}
}

// copyWebsocketFrame tests

func TestCopyWebsocketFrame_NoRecorder(t *testing.T) {
	ep := New(newTestConfig(), nil)
	buf := &bytes.Buffer{}

	// Build a minimal WebSocket frame (FIN=1, opcode=1 (text), masked, length=5)
	frame := wsFrame(t, true, 1, true, []byte("hello"))
	r := bytes.NewReader(frame)
	w := &bytes.Buffer{}
	ro := &xrecorder.HandlerRecorderObject{}

	err := ep.copyWebsocketFrame(w, r, buf, "client", ro)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify output matches input
	if !bytes.Equal(frame, w.Bytes()) {
		t.Error("output does not match input")
	}
}

// wsFrame builds a minimal unmasked WebSocket frame.
func wsFrame(t *testing.T, fin bool, opCode byte, masked bool, payload []byte) []byte {
	t.Helper()
	var header byte
	if fin {
		header |= 0x80
	}
	header |= opCode & 0x0f

	var maskBit byte
	if masked {
		maskBit = 0x80
	}

	var buf bytes.Buffer
	buf.WriteByte(header)

	if len(payload) < 126 {
		buf.WriteByte(byte(len(payload)) | maskBit)
	} else if len(payload) < 65536 {
		buf.WriteByte(126 | maskBit)
		buf.WriteByte(byte(len(payload) >> 8))
		buf.WriteByte(byte(len(payload)))
	} else {
		buf.WriteByte(127 | maskBit)
		for i := 7; i >= 0; i-- {
			buf.WriteByte(byte(uint64(len(payload)) >> (8 * i)))
		}
	}

	if masked {
		maskKey := []byte{0x01, 0x02, 0x03, 0x04}
		buf.Write(maskKey)
		for i, p := range payload {
			buf.WriteByte(p ^ maskKey[i%4])
		}
	} else {
		buf.Write(payload)
	}

	return buf.Bytes()
}

// sniffingWebsocketFrame test
func TestEntrypoint_WebsocketSniffingCodePaths(t *testing.T) {
	// Verify that the copyWebsocketFrame function handles both client and server
	// directions and properly tracks InputBytes/OutputBytes.
	buf := &bytes.Buffer{}
	r := bytes.NewReader(wsFrame(t, true, 1, false, []byte("hello")))
	w := &bytes.Buffer{}
	ro := &xrecorder.HandlerRecorderObject{}

	ep := New(newTestConfig(), nil)
	err := ep.copyWebsocketFrame(w, r, buf, "client", ro)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ro.InputBytes == 0 {
		t.Error("expected non-zero InputBytes for client direction")
	}
	if ro.OutputBytes != 0 {
		t.Error("expected 0 OutputBytes for client direction")
	}

	// Server direction
	r2 := bytes.NewReader(wsFrame(t, true, 1, false, []byte("world")))
	w2 := &bytes.Buffer{}
	ro2 := &xrecorder.HandlerRecorderObject{}
	err = ep.copyWebsocketFrame(w2, r2, buf, "server", ro2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ro2.OutputBytes == 0 {
		t.Error("expected non-zero OutputBytes for server direction")
	}
	if ro2.InputBytes != 0 {
		t.Error("expected 0 InputBytes for server direction")
	}
}