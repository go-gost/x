package sniffing

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/recorder"
	xlogger "github.com/go-gost/x/logger"
	xrecorder "github.com/go-gost/x/recorder"
)

// =============================================================================
// Test Helpers (local mocks)
// =============================================================================

type noopRecorder struct{}

func (n *noopRecorder) Record(_ context.Context, _ []byte, _ ...recorder.RecordOption) error {
	return nil
}

type mockBypass struct {
	contains  bool
	whitelist bool
}

func (m *mockBypass) Contains(_ context.Context, _, _ string, _ ...bypass.Option) bool {
	return m.contains
}

func (m *mockBypass) IsWhitelist() bool { return m.whitelist }

// =============================================================================
// Pure Function Tests
// =============================================================================

func TestClampBodySize(t *testing.T) {
	tests := []struct {
		name string
		opts *recorder.Options
		want int
	}{
		{"nil opts", nil, 0},
		{"HTTPBody disabled", &recorder.Options{HTTPBody: false, MaxBodySize: 1000}, 0},
		{"zero MaxBodySize defaults to DefaultBodySize", &recorder.Options{HTTPBody: true, MaxBodySize: 0}, DefaultBodySize},
		{"negative MaxBodySize defaults", &recorder.Options{HTTPBody: true, MaxBodySize: -1}, DefaultBodySize},
		{"valid MaxBodySize within bounds", &recorder.Options{HTTPBody: true, MaxBodySize: 1024}, 1024},
		{"MaxBodySize capped at MaxBodySize", &recorder.Options{HTTPBody: true, MaxBodySize: 10 * 1024 * 1024}, MaxBodySize},
		{"exact MaxBodySize", &recorder.Options{HTTPBody: true, MaxBodySize: MaxBodySize}, MaxBodySize},
		{"exact DefaultBodySize", &recorder.Options{HTTPBody: true, MaxBodySize: DefaultBodySize}, DefaultBodySize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clampBodySize(tt.opts); got != tt.want {
				t.Errorf("clampBodySize() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		defaultPort string
		want        string
	}{
		{"empty host", "", "443", ""},
		{"host with port", "example.com:8080", "443", "example.com:8080"},
		{"host without port, default 80", "example.com", "80", "example.com:80"},
		{"host without port, default 443", "example.com", "443", "example.com:443"},
		{"IPv4 with port", "127.0.0.1:9090", "80", "127.0.0.1:9090"},
		{"IPv4 without port", "127.0.0.1", "80", "127.0.0.1:80"},
		{"IPv6 bracketed with port", "[::1]:8080", "443", "[::1]:8080"},
		{"IPv6 bracketed without port", "[::1]", "443", "[::1]:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeHost(tt.host, tt.defaultPort)
			if got != tt.want {
				t.Errorf("normalizeHost(%q, %q) = %q, want %q", tt.host, tt.defaultPort, got, tt.want)
			}
		})
	}
}

func TestEffectiveReadTimeout(t *testing.T) {
	tests := []struct {
		name      string
		snifferTO time.Duration
		want      time.Duration
	}{
		{"zero defaults to DefaultReadTimeout", 0, DefaultReadTimeout},
		{"sniffer timeout set", 10 * time.Second, 10 * time.Second},
		{"another sniffer timeout", 5 * time.Second, 5 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Sniffer{ReadTimeout: tt.snifferTO}
			got := h.effectiveReadTimeout()
			if got != tt.want {
				t.Errorf("effectiveReadTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpgradeType(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   string
	}{
		{
			"websocket upgrade",
			http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}},
			"websocket",
		},
		{
			"h2c upgrade",
			http.Header{"Connection": {"Upgrade"}, "Upgrade": {"h2c"}},
			"h2c",
		},
		{
			"no upgrade header",
			http.Header{"Connection": {"keep-alive"}},
			"",
		},
		{
			"empty header",
			http.Header{},
			"",
		},
		{
			"connection has upgrade but no upgrade header",
			http.Header{"Connection": {"Upgrade"}},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := upgradeType(tt.header); got != tt.want {
				t.Errorf("upgradeType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWrapErr(t *testing.T) {
	err := wrapErr("read response", io.EOF)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "read response: EOF" {
		t.Errorf("error = %q, want %q", err.Error(), "read response: EOF")
	}
	if !errors.Is(err, io.EOF) {
		t.Error("errors.Is should unwrap to EOF")
	}
}

// =============================================================================
// HandleOptions Tests
// =============================================================================

func TestWithService(t *testing.T) {
	opts := &HandleOptions{}
	WithService("mysvc")(opts)
	if opts.service != "mysvc" {
		t.Errorf("service = %q, want %q", opts.service, "mysvc")
	}
}

func TestWithDial(t *testing.T) {
	opts := &HandleOptions{}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return nil, nil
	}
	WithDial(dial)(opts)
	if opts.dial == nil {
		t.Error("dial should be set")
	}
}

func TestWithDialTLS(t *testing.T) {
	opts := &HandleOptions{}
	dialTLS := func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
		return nil, nil
	}
	WithDialTLS(dialTLS)(opts)
	if opts.dialTLS == nil {
		t.Error("dialTLS should be set")
	}
}

func TestWithBypass(t *testing.T) {
	opts := &HandleOptions{}
	bp := &mockBypass{contains: true}
	WithBypass(bp)(opts)
	if opts.bypass != bp {
		t.Errorf("bypass not set")
	}
}

func TestWithRecorderObject(t *testing.T) {
	opts := &HandleOptions{}
	ro := &xrecorder.HandlerRecorderObject{}
	WithRecorderObject(ro)(opts)
	if opts.recorderObject != ro {
		t.Errorf("recorderObject not set")
	}
}

func TestWithLog(t *testing.T) {
	opts := &HandleOptions{}
	log := xlogger.Nop()
	WithLog(log)(opts)
	if opts.log != log {
		t.Errorf("log not set")
	}
}

// =============================================================================
// HandleHTTP Integration Tests
// =============================================================================

func TestHandleHTTP_BasicProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK from upstream"))
	}))
	defer upstream.Close()

	h := &Sniffer{
		ReadTimeout: 5 * time.Second,
		Recorder:    &noopRecorder{},
	}
	ro := &xrecorder.HandlerRecorderObject{}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.HandleHTTP(context.Background(), "tcp", serverConn,
			WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("tcp", upstream.Listener.Addr().String())
			}),
			WithRecorderObject(ro),
			WithLog(xlogger.Nop()),
		)
	}()

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	if err := req.Write(clientConn); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	clientConn.Close()
	if err := <-errCh; err != nil {
		t.Logf("HandleHTTP returned: %v", err)
	}

	if ro.SrcAddr == "" {
		t.Error("SrcAddr should be populated")
	}
	if ro.DstAddr == "" {
		t.Error("DstAddr should be populated")
	}
}

func TestHandleHTTP_HTTP2Detection(t *testing.T) {
	h := &Sniffer{
		ReadTimeout: 5 * time.Second,
		Recorder:    &noopRecorder{},
	}
	ro := &xrecorder.HandlerRecorderObject{
		RemoteAddr: "127.0.0.1:12345",
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.HandleHTTP(context.Background(), "tcp", serverConn,
			WithRecorderObject(ro),
			WithLog(xlogger.Nop()),
		)
	}()

	clientConn.Write([]byte("PRI * HTTP/2.0\r\n\r\n"))

	clientConn.Close()

	err := <-errCh
	if err == nil {
		t.Log("HandleHTTP returned nil (expected error from incomplete h2 preface)")
	}
}

func TestHandleHTTP_DialError(t *testing.T) {
	h := &Sniffer{
		ReadTimeout: 5 * time.Second,
		Recorder:    &noopRecorder{},
	}
	ro := &xrecorder.HandlerRecorderObject{}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.HandleHTTP(context.Background(), "tcp", serverConn,
			WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, io.ErrUnexpectedEOF
			}),
			WithRecorderObject(ro),
			WithLog(xlogger.Nop()),
		)
	}()

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Write(clientConn)
	clientConn.Close() // unblock server-side ReadRequest loop

	err := <-errCh
	if err == nil {
		t.Error("expected error from failed dial, got nil")
	}
}

func TestHandleHTTP_HTTP10Request(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("HTTP/1.0 OK"))
	}))
	defer upstream.Close()

	h := &Sniffer{
		ReadTimeout: 5 * time.Second,
		Recorder:    &noopRecorder{},
	}
	ro := &xrecorder.HandlerRecorderObject{}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.HandleHTTP(context.Background(), "tcp", serverConn,
			WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("tcp", upstream.Listener.Addr().String())
			}),
			WithRecorderObject(ro),
			WithLog(xlogger.Nop()),
		)
	}()

	clientConn.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"))

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	clientConn.Close()
	<-errCh
}

// =============================================================================
// copyWebsocketFrame Tests
// =============================================================================

func TestCopyWebsocketFrame_Basic(t *testing.T) {
	h := &Sniffer{
		Recorder:        &noopRecorder{},
		RecorderOptions: &recorder.Options{HTTPBody: false},
	}

	payload := []byte("hi")
	mask := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	maskedPayload := make([]byte, len(payload))
	for i := range payload {
		maskedPayload[i] = payload[i] ^ mask[i%4]
	}

	var frame bytes.Buffer
	frame.WriteByte(0x81)      // FIN + text opcode
	frame.WriteByte(0x82)      // MASK + len=2
	frame.Write(mask)
	frame.Write(maskedPayload)

	w := &bytes.Buffer{}
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.copyWebsocketFrame(w, &frame, &bytes.Buffer{}, "client", ro)
	if err != nil {
		t.Fatal(err)
	}

	if ro.Websocket == nil {
		t.Fatal("Websocket recorder object should be populated")
	}
	if ro.Websocket.OpCode != 1 {
		t.Errorf("opcode = %d, want 1 (text)", ro.Websocket.OpCode)
	}
	if !ro.Websocket.Masked {
		t.Error("client frame should be marked as masked")
	}
	if ro.InputBytes == 0 {
		t.Error("InputBytes should be non-zero for client direction")
	}
}

func TestCopyWebsocketFrame_WithBodyRecording(t *testing.T) {
	h := &Sniffer{
		Recorder:        &noopRecorder{},
		RecorderOptions: &recorder.Options{HTTPBody: true, MaxBodySize: 1024},
	}

	payload := []byte("hello ws")
	var frame bytes.Buffer
	frame.WriteByte(0x81)               // FIN + text
	frame.WriteByte(byte(len(payload))) // MASK=0, len
	frame.Write(payload)

	w := &bytes.Buffer{}
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.copyWebsocketFrame(w, &frame, &bytes.Buffer{}, "server", ro)
	if err != nil {
		t.Fatal(err)
	}

	if ro.Websocket == nil {
		t.Fatal("Websocket recorder object should be populated")
	}
	if string(ro.Websocket.Payload) != "hello ws" {
		t.Errorf("payload = %q, want %q", ro.Websocket.Payload, "hello ws")
	}
	if ro.Websocket.Masked {
		t.Error("server frame should be marked as unmasked")
	}
	if ro.OutputBytes == 0 {
		t.Error("OutputBytes should be non-zero for server direction")
	}
}

func TestCopyWebsocketFrame_EmptyPayload(t *testing.T) {
	h := &Sniffer{
		Recorder:        &noopRecorder{},
		RecorderOptions: &recorder.Options{HTTPBody: true, MaxBodySize: 1024},
	}

	var frame bytes.Buffer
	frame.WriteByte(0x81) // FIN + text
	frame.WriteByte(0x00) // MASK=0, len=0

	w := &bytes.Buffer{}
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.copyWebsocketFrame(w, &frame, &bytes.Buffer{}, "server", ro)
	if err != nil {
		t.Fatal(err)
	}

	if ro.Websocket == nil {
		t.Fatal("Websocket recorder object should be populated")
	}
	if ro.Websocket.Length != 0 {
		t.Errorf("payload length = %d, want 0", ro.Websocket.Length)
	}
}

func TestCopyWebsocketFrame_ServerWithoutBodyRecording(t *testing.T) {
	h := &Sniffer{
		Recorder:        &noopRecorder{},
		RecorderOptions: &recorder.Options{HTTPBody: false},
	}

	payload := []byte("data")
	var frame bytes.Buffer
	frame.WriteByte(0x82)               // FIN + binary
	frame.WriteByte(byte(len(payload))) // MASK=0, len
	frame.Write(payload)

	w := &bytes.Buffer{}
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.copyWebsocketFrame(w, &frame, &bytes.Buffer{}, "server", ro)
	if err != nil {
		t.Fatal(err)
	}

	if ro.Websocket == nil {
		t.Fatal("Websocket recorder object should be populated")
	}
	if ro.Websocket.Payload != nil {
		t.Error("payload should be nil when body recording is disabled")
	}
	if ro.Websocket.OpCode != 2 {
		t.Errorf("opcode = %d, want 2 (binary)", ro.Websocket.OpCode)
	}
	if ro.OutputBytes == 0 {
		t.Error("OutputBytes should be non-zero for server direction")
	}
	if ro.InputBytes != 0 {
		t.Error("InputBytes should be zero for server direction")
	}
}

func TestCopyWebsocketFrame_MaskedFrame(t *testing.T) {
	h := &Sniffer{
		Recorder:        &noopRecorder{},
		RecorderOptions: &recorder.Options{HTTPBody: false},
	}

	payload := []byte("secret")
	mask := []byte{0x12, 0x34, 0x56, 0x78}
	maskedPayload := make([]byte, len(payload))
	for i := range payload {
		maskedPayload[i] = payload[i] ^ mask[i%4]
	}

	var frame bytes.Buffer
	frame.WriteByte(0x81)                      // FIN + text
	frame.WriteByte(0x80 | byte(len(payload))) // MASK=1, len
	frame.Write(mask)
	frame.Write(maskedPayload)

	w := &bytes.Buffer{}
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.copyWebsocketFrame(w, &frame, &bytes.Buffer{}, "client", ro)
	if err != nil {
		t.Fatal(err)
	}

	if ro.Websocket == nil {
		t.Fatal("Websocket recorder object should be populated")
	}
	if !ro.Websocket.Masked {
		t.Error("client frame should be masked")
	}
	written := w.Bytes()
	if len(written) < 2+len(payload) {
		t.Fatalf("written frame too short: %d bytes", len(written))
	}
	if written[0] != 0x81 {
		t.Errorf("first byte = 0x%02x, want 0x81", written[0])
	}
	if written[1]&0x80 != 0x80 {
		t.Error("mask bit should be preserved")
	}
}

// =============================================================================
// handleUpgradeResponse Tests
// =============================================================================

func TestHandleUpgradeResponse_TypeMismatch(t *testing.T) {
	h := &Sniffer{}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		Header: http.Header{
			"Connection": {"Upgrade"},
			"Upgrade":    {"h2c"},
		},
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	err := h.handleUpgradeResponse(context.Background(), serverConn, clientConn, req, res,
		&xrecorder.HandlerRecorderObject{}, xlogger.Nop())
	if err == nil {
		t.Fatal("expected type mismatch error, got nil")
	}
}

func TestHandleUpgradeResponse_NonWebsocket(t *testing.T) {
	h := &Sniffer{Websocket: false}

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "h2c")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Connection": {"Upgrade"},
			"Upgrade":    {"h2c"},
		},
	}

	errCh := make(chan error, 1)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		errCh <- h.handleUpgradeResponse(context.Background(), serverConn, clientConn, req, res,
			&xrecorder.HandlerRecorderObject{}, xlogger.Nop())
	}()

	br := bufio.NewReader(clientConn)
	readResp, readErr := http.ReadResponse(br, req)
	if readErr != nil {
		t.Fatalf("reading upgrade response: %v", readErr)
	}
	if readResp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("status = %d, want %d", readResp.StatusCode, http.StatusSwitchingProtocols)
	}

	clientConn.Close()
	serverConn.Close()
	<-errCh
}

// =============================================================================
// serveH2 unit test (client preface)
// =============================================================================

func TestServeH2_InvalidPreface(t *testing.T) {
	h := &Sniffer{
		ReadTimeout: 5 * time.Second,
		Recorder:    &noopRecorder{},
	}
	ho := &HandleOptions{
		log:            xlogger.Nop(),
		recorderObject: &xrecorder.HandlerRecorderObject{},
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		clientConn.Write([]byte("XXXXXX"))
	}()

	err := h.serveH2(context.Background(), "tcp", serverConn, ho)
	if err == nil {
		t.Error("expected error from invalid h2 preface, got nil")
	}
}
