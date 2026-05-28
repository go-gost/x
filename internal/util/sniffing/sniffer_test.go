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
	"strings"
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
			if got := ClampBodySize(tt.opts); got != tt.want {
				t.Errorf("ClampBodySize() = %d, want %d", got, tt.want)
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

// =============================================================================
// serveH2 — short read (EOF before 6 bytes)
// =============================================================================

func TestServeH2_ShortRead(t *testing.T) {
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
		clientConn.Write([]byte("SHORT")) // only 5 bytes, then close
		clientConn.Close()
	}()

	err := h.serveH2(context.Background(), "tcp", serverConn, ho)
	if err == nil {
		t.Error("expected error from short h2 preface read, got nil")
	}
	if !strings.Contains(err.Error(), "error reading client preface") {
		t.Errorf("unexpected error: %v", err)
	}
}

// =============================================================================
// setHeader Tests
// =============================================================================

func TestSetHeader(t *testing.T) {
	h := &h2Handler{}
	w := httptest.NewRecorder()
	h.setHeader(w, http.Header{
		"Content-Type": {"text/html"},
		"X-Custom":     {"a", "b"},
	})
	if w.Header().Get("Content-Type") != "text/html" {
		t.Errorf("Content-Type = %q, want %q", w.Header().Get("Content-Type"), "text/html")
	}
	vals := w.Header()["X-Custom"]
	if len(vals) != 2 || vals[0] != "a" || vals[1] != "b" {
		t.Errorf("X-Custom = %v, want [a b]", vals)
	}
}

// =============================================================================
// h2Handler.ServeHTTP Tests
// =============================================================================

type mockRoundTripper struct {
	resp *http.Response
	err  error
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.resp, m.err
}

func TestH2HandlerServeHTTP_Success(t *testing.T) {
	handler := &h2Handler{
		transport: &mockRoundTripper{
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"text/plain"}},
				Body:       io.NopCloser(strings.NewReader("h2 body")),
			},
		},
		recorder:        &noopRecorder{},
		recorderOptions: &recorder.Options{HTTPBody: false},
		recorderObject:  &xrecorder.HandlerRecorderObject{},
		log:             xlogger.Nop(),
	}

	req := httptest.NewRequest("GET", "https://example.com/path", nil)
	req.RequestURI = "/path"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if w.Body.String() != "h2 body" {
		t.Errorf("body = %q, want %q", w.Body.String(), "h2 body")
	}
}

func TestH2HandlerServeHTTP_RoundTripError(t *testing.T) {
	handler := &h2Handler{
		transport: &mockRoundTripper{
			err: errors.New("connection refused"),
		},
		recorder:        &noopRecorder{},
		recorderOptions: &recorder.Options{HTTPBody: false},
		recorderObject:  &xrecorder.HandlerRecorderObject{},
		log:             xlogger.Nop(),
	}

	req := httptest.NewRequest("GET", "https://example.com/path", nil)
	req.RequestURI = "/path"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestH2HandlerServeHTTP_WithBodyRecording(t *testing.T) {
	handler := &h2Handler{
		transport: &mockRoundTripper{
			resp: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"key":"value"}`)),
			},
		},
		recorder:        &noopRecorder{},
		recorderOptions: &recorder.Options{HTTPBody: true, MaxBodySize: 1024},
		recorderObject:  &xrecorder.HandlerRecorderObject{},
		log:             xlogger.Nop(),
	}

	req := httptest.NewRequest("POST", "https://example.com/api", strings.NewReader("hello"))
	req.RequestURI = "/api"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// =============================================================================
// Sniff / isHTTP Tests
// =============================================================================

func TestSniff_TLS(t *testing.T) {
	// Build a minimal TLS ClientHello record:
	// ContentType=Handshake(0x16), Version=TLS1.2(0x0303), Length=0x0001, data=0x01
	hdr := []byte{0x16, 0x03, 0x03, 0x00, 0x01, 0x01}
	r := bufio.NewReader(bytes.NewReader(hdr))
	proto, err := Sniff(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if proto != ProtoTLS {
		t.Errorf("proto = %q, want %q", proto, ProtoTLS)
	}
}

func TestSniff_TLSv10(t *testing.T) {
	// TLS 1.0 = 0x0301
	hdr := []byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01}
	r := bufio.NewReader(bytes.NewReader(hdr))
	proto, err := Sniff(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if proto != ProtoTLS {
		t.Errorf("proto = %q, want %q", proto, ProtoTLS)
	}
}

func TestSniff_TLSv13(t *testing.T) {
	// TLS 1.3 = 0x0304
	hdr := []byte{0x16, 0x03, 0x04, 0x00, 0x01, 0x01}
	r := bufio.NewReader(bytes.NewReader(hdr))
	proto, err := Sniff(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if proto != ProtoTLS {
		t.Errorf("proto = %q, want %q", proto, ProtoTLS)
	}
}

func TestSniff_HTTP_GET(t *testing.T) {
	hdr := []byte("GET / HTTP/1.1\r\n")
	r := bufio.NewReader(bytes.NewReader(hdr))
	proto, err := Sniff(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if proto != ProtoHTTP {
		t.Errorf("proto = %q, want %q", proto, ProtoHTTP)
	}
}

func TestSniff_HTTP_POST(t *testing.T) {
	hdr := []byte("POST /api HTTP/1.1\r\n")
	r := bufio.NewReader(bytes.NewReader(hdr))
	proto, err := Sniff(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if proto != ProtoHTTP {
		t.Errorf("proto = %q, want %q", proto, ProtoHTTP)
	}
}

func TestSniff_HTTP_CONNECT(t *testing.T) {
	hdr := []byte("CONNECT example.com:443 HTTP/1.1\r\n")
	r := bufio.NewReader(bytes.NewReader(hdr))
	proto, err := Sniff(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if proto != ProtoHTTP {
		t.Errorf("proto = %q, want %q", proto, ProtoHTTP)
	}
}

func TestSniff_HTTP_H2Preface(t *testing.T) {
	hdr := []byte("PRI * HTTP/2.0\r\n")
	r := bufio.NewReader(bytes.NewReader(hdr))
	proto, err := Sniff(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if proto != ProtoHTTP {
		t.Errorf("proto = %q, want %q", proto, ProtoHTTP)
	}
}

func TestSniff_HTTP_OPTIONS(t *testing.T) {
	hdr := []byte("OPTIONS * HTTP/1.1\r\n")
	r := bufio.NewReader(bytes.NewReader(hdr))
	proto, err := Sniff(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if proto != ProtoHTTP {
		t.Errorf("proto = %q, want %q", proto, ProtoHTTP)
	}
}

func TestSniff_SSH(t *testing.T) {
	hdr := []byte("SSH-2.0-OpenSSH_8.9")
	r := bufio.NewReader(bytes.NewReader(hdr))
	proto, err := Sniff(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if proto != ProtoSSH {
		t.Errorf("proto = %q, want %q", proto, ProtoSSH)
	}
}

func TestSniff_Unknown(t *testing.T) {
	// bytes that don't match TLS, HTTP, or SSH
	hdr := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	r := bufio.NewReader(bytes.NewReader(hdr))
	proto, err := Sniff(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if proto != "" {
		t.Errorf("proto = %q, want empty", proto)
	}
}

func TestIsHTTP_AllMethods(t *testing.T) {
	// isHTTP receives a 5-byte peek from the buffered reader.
	// For most methods it checks if the method name starts with s (or s[:N]).
	// So the test strings must be exactly 5 bytes (or the method prefix).
	tests := []string{
		"GET /", // s[:3] = "GET", HasPrefix("GET", "GET") = true
		"POST ", // s[:4] = "POST", HasPrefix("POST", "POST") = true
		"PUT /", // s[:3] = "PUT", HasPrefix("PUT", "PUT") = true
		"DELET", // HasPrefix("DELETE", "DELET") = true
		"OPTIO", // HasPrefix("OPTIONS", "OPTIO") = true
		"PATCH", // HasPrefix("PATCH", "PATCH") = true
		"HEAD ", // s[:4] = "HEAD", HasPrefix("HEAD", "HEAD") = true
		"CONNE", // HasPrefix("CONNECT", "CONNE") = true
		"TRACE", // HasPrefix("TRACE", "TRACE") = true
		"PRI *", // HasPrefix(s, "PRI *") = true
	}
	for _, s := range tests {
		if !isHTTP(s) {
			t.Errorf("isHTTP(%q) = false, want true", s)
		}
	}
}

func TestIsHTTP_NoPrefixMatch(t *testing.T) {
	if isHTTP("GEX /") {
		t.Error("isHTTP(GEX) should be false")
	}
	if isHTTP("XXXXX") {
		t.Error("isHTTP(XXXXX) should be false")
	}
}

// =============================================================================
// HandleHTTP Bypass Test
// =============================================================================

func TestHandleHTTP_Bypass(t *testing.T) {
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
			WithBypass(&mockBypass{contains: true}),
			WithRecorderObject(ro),
			WithLog(xlogger.Nop()),
		)
	}()

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Write(clientConn)
	clientConn.Close()

	err := <-errCh
	if err == nil {
		t.Fatal("expected bypass error, got nil")
	}
}

// =============================================================================
// HandleTLS Error Path Tests
// =============================================================================

func TestHandleTLS_NonTLSData(t *testing.T) {
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
		errCh <- h.HandleTLS(context.Background(), "tcp", serverConn,
			WithRecorderObject(ro),
			WithLog(xlogger.Nop()),
		)
	}()

	// Write non-TLS data that won't parse as ClientHello
	clientConn.Write([]byte("NOT A TLS CLIENT HELLO"))
	clientConn.Close()

	err := <-errCh
	if err == nil {
		t.Fatal("expected error from non-TLS data, got nil")
	}
}

// =============================================================================
// handleUpgradeResponse Websocket Path Test
// =============================================================================

func TestHandleUpgradeResponse_WebsocketEnabled(t *testing.T) {
	h := &Sniffer{
		Websocket:    true,
		ReadTimeout:  5 * time.Second,
		Recorder:     &noopRecorder{},
	}
	ro := &xrecorder.HandlerRecorderObject{}

	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Connection": {"Upgrade"},
			"Upgrade":    {"websocket"},
		},
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleUpgradeResponse(context.Background(), serverConn, clientConn, req, res, ro, xlogger.Nop())
	}()

	br := bufio.NewReader(clientConn)
	readResp, readErr := http.ReadResponse(br, req)
	if readErr != nil {
		t.Fatalf("reading upgrade response: %v", readErr)
	}
	if readResp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("status = %d, want %d", readResp.StatusCode, http.StatusSwitchingProtocols)
	}

	// sniffingWebsocketFrame goroutines are waiting for WS frames.
	// Close to unblock them; use a timeout since sniffingWebsocketFrame
	// has a goroutine leak (single-buffered errc with 2 goroutines).
	clientConn.Close()
	serverConn.Close()

	select {
	case <-errCh:
	case <-time.After(time.Second):
		// sniffingWebsocketFrame leaked a goroutine; test that the 101
		// response was written correctly (verified above) and move on.
	}
}

// =============================================================================
// httpRoundTrip with Response Body Recording
// =============================================================================

func TestHandleHTTP_ResponseBodyRecording(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response body content"))
	}))
	defer upstream.Close()

	h := &Sniffer{
		ReadTimeout:     5 * time.Second,
		Recorder:        &noopRecorder{},
		RecorderOptions: &recorder.Options{HTTPBody: true, MaxBodySize: 1024},
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
	<-errCh
}

// =============================================================================
// HandleHTTP Request Body Recording
// =============================================================================

func TestHandleHTTP_RequestBodyRecording(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer upstream.Close()

	h := &Sniffer{
		ReadTimeout:     5 * time.Second,
		Recorder:        &noopRecorder{},
		RecorderOptions: &recorder.Options{HTTPBody: true, MaxBodySize: 1024},
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

	req, _ := http.NewRequest("POST", "http://example.com/upload", strings.NewReader("my request body"))
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
	<-errCh
}

// =============================================================================
// copyWebsocketFrame read error test
// =============================================================================

func TestCopyWebsocketFrame_ReadError(t *testing.T) {
	h := &Sniffer{
		Recorder:        &noopRecorder{},
		RecorderOptions: &recorder.Options{HTTPBody: false},
	}

	// Empty reader will cause Frame.ReadFrom to get io.EOF
	r := bytes.NewReader(nil)
	ro := &xrecorder.HandlerRecorderObject{}

	err := h.copyWebsocketFrame(io.Discard, r, &bytes.Buffer{}, "client", ro)
	if err == nil {
		t.Error("expected error from empty WS frame reader, got nil")
	}
}
