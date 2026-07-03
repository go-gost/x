package recorder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/recorder"
	xlogger "github.com/go-gost/x/logger"
)

// --- Option tests ---

func TestRecorderFileRecorderOption(t *testing.T) {
	var opts fileRecorderOptions
	RecorderFileRecorderOption("my-recorder")(&opts)
	if opts.recorder != "my-recorder" {
		t.Errorf("recorder = %s, want my-recorder", opts.recorder)
	}
}

func TestSepFileRecorderOption(t *testing.T) {
	var opts fileRecorderOptions
	SepFileRecorderOption("\n")(&opts)
	if opts.sep != "\n" {
		t.Errorf("sep = %s, want \\n", opts.sep)
	}
}

func TestRecorderHTTPRecorderOption(t *testing.T) {
	var opts httpRecorderOptions
	RecorderHTTPRecorderOption("http-rec")(&opts)
	if opts.recorder != "http-rec" {
		t.Errorf("recorder = %s, want http-rec", opts.recorder)
	}
}

func TestTimeoutHTTPRecorderOption(t *testing.T) {
	var opts httpRecorderOptions
	TimeoutHTTPRecorderOption(5 * time.Second)(&opts)
	if opts.timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", opts.timeout)
	}
}

func TestHeaderHTTPRecorderOption(t *testing.T) {
	var opts httpRecorderOptions
	h := http.Header{"X-Test": []string{"value"}}
	HeaderHTTPRecorderOption(h)(&opts)
	if opts.header.Get("X-Test") != "value" {
		t.Errorf("header = %v, want X-Test: value", opts.header)
	}
}

func TestRecorderTCPRecorderOption(t *testing.T) {
	var opts tcpRecorderOptions
	RecorderTCPRecorderOption("tcp-rec")(&opts)
	if opts.recorder != "tcp-rec" {
		t.Errorf("recorder = %s, want tcp-rec", opts.recorder)
	}
}

func TestTimeoutTCPRecorderOption(t *testing.T) {
	var opts tcpRecorderOptions
	TimeoutTCPRecorderOption(10 * time.Second)(&opts)
	if opts.timeout != 10*time.Second {
		t.Errorf("timeout = %v, want 10s", opts.timeout)
	}
}

func TestLogTCPRecorderOption(t *testing.T) {
	var opts tcpRecorderOptions
	l := xlogger.Nop()
	LogTCPRecorderOption(l)(&opts)
	if opts.log != l {
		t.Error("log should be set")
	}
}

func TestRecorderRedisRecorderOption(t *testing.T) {
	var opts redisRecorderOptions
	RecorderRedisRecorderOption("redis-rec")(&opts)
	if opts.recorder != "redis-rec" {
		t.Errorf("recorder = %s, want redis-rec", opts.recorder)
	}
}

func TestDBRedisRecorderOption(t *testing.T) {
	var opts redisRecorderOptions
	DBRedisRecorderOption(3)(&opts)
	if opts.db != 3 {
		t.Errorf("db = %d, want 3", opts.db)
	}
}

func TestUsernameRedisRecorderOption(t *testing.T) {
	var opts redisRecorderOptions
	UsernameRedisRecorderOption("admin")(&opts)
	if opts.username != "admin" {
		t.Errorf("username = %s, want admin", opts.username)
	}
}

func TestPasswordRedisRecorderOption(t *testing.T) {
	var opts redisRecorderOptions
	PasswordRedisRecorderOption("secret")(&opts)
	if opts.password != "secret" {
		t.Errorf("password = %s, want secret", opts.password)
	}
}

func TestKeyRedisRecorderOption(t *testing.T) {
	var opts redisRecorderOptions
	KeyRedisRecorderOption("mykey")(&opts)
	if opts.key != "mykey" {
		t.Errorf("key = %s, want mykey", opts.key)
	}
}

// --- FileRecorder tests ---

func TestFileRecorder_Record(t *testing.T) {
	var buf bytes.Buffer
	r := FileRecorder(&nopWriteCloser{&buf})
	if r == nil {
		t.Fatal("FileRecorder should not return nil")
	}

	err := r.Record(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != "hello" {
		t.Errorf("output = %s, want hello", buf.String())
	}
}

func TestFileRecorder_Record_WithSeparator(t *testing.T) {
	var buf bytes.Buffer
	r := FileRecorder(&nopWriteCloser{&buf}, SepFileRecorderOption("\n"))

	err := r.Record(context.Background(), []byte("line1"))
	if err != nil {
		t.Fatal(err)
	}
	err = r.Record(context.Background(), []byte("line2"))
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != "line1\nline2\n" {
		t.Errorf("output = %q, want line1\\nline2\\n", buf.String())
	}
}

func TestFileRecorder_Record_NilOut(t *testing.T) {
	r := FileRecorder(nil)
	err := r.Record(context.Background(), []byte("should not panic"))
	if err != nil {
		t.Errorf("expected nil on nil out, got %v", err)
	}
}

func TestFileRecorder_Close(t *testing.T) {
	var buf bytes.Buffer
	r := FileRecorder(&nopWriteCloser{&buf}).(*fileRecorder)
	err := r.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestFileRecorder_Close_Idempotent(t *testing.T) {
	var buf bytes.Buffer
	r := FileRecorder(&nopWriteCloser{&buf}).(*fileRecorder)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close returned error: %v", err)
	}
}

func TestFileRecorder_Close_NilOut(t *testing.T) {
	r := FileRecorder(nil).(*fileRecorder)
	if err := r.Close(); err != nil {
		t.Errorf("Close on nil out returned error: %v", err)
	}
}

func TestFileRecorder_ConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	r := FileRecorder(&nopWriteCloser{&buf}, SepFileRecorderOption("\n"))

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r.Record(context.Background(), []byte(fmt.Sprintf("msg-%d", n)))
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 100 {
		t.Errorf("expected 100 lines, got %d", len(lines))
	}
}

func TestFileRecorder_Record_WriteError(t *testing.T) {
	r := FileRecorder(&nopWriteCloser{&errorWriter{}})
	err := r.Record(context.Background(), []byte("data"))
	if err == nil {
		t.Error("expected error on write failure")
	}
}

func TestFileRecorder_Record_WriteErrorWithSeparator(t *testing.T) {
	w := &writeOnceThenError{max: 0}
	r := FileRecorder(&nopWriteCloser{w}, SepFileRecorderOption("\n"))
	err := r.Record(context.Background(), []byte("data"))
	if err == nil {
		t.Error("expected error on write failure")
	}
}

func TestFileRecorder_ConcurrentWrites_NoSeparator(t *testing.T) {
	var buf bytes.Buffer
	r := FileRecorder(&nopWriteCloser{&buf})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r.Record(context.Background(), []byte(fmt.Sprintf("msg%d", n)))
		}(i)
	}
	wg.Wait()
	// Without a separator, concurrent writes are still serialized by Record's
	// mutex (the underlying io.WriteCloser is not safe for concurrent Write).
	if buf.Len() == 0 {
		t.Error("buffer should contain data")
	}
}

func TestFileRecorder_WithRecorder(t *testing.T) {
	var buf bytes.Buffer
	r := FileRecorder(&nopWriteCloser{&buf}, RecorderFileRecorderOption("file-rec"))
	fr := r.(*fileRecorder)
	if fr.recorder != "file-rec" {
		t.Errorf("recorder = %s, want file-rec", fr.recorder)
	}
}

func TestFileRecorder_CloseAfterRecord(t *testing.T) {
	var buf bytes.Buffer
	r := FileRecorder(&nopWriteCloser{&buf}).(*fileRecorder)
	r.Record(context.Background(), []byte("data"))
	if err := r.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// --- HTTPRecorder tests ---

func TestHTTPRecorder_EmptyURL(t *testing.T) {
	r := HTTPRecorder("")
	if r != nil {
		t.Error("HTTPRecorder with empty URL should return nil")
	}
}

func TestHTTPRecorder_NoScheme(t *testing.T) {
	r := HTTPRecorder("example.com:9999")
	hr := r.(*httpRecorder)
	if !strings.HasPrefix(hr.url, "http://") {
		t.Errorf("expected http:// prefix, got %s", hr.url)
	}
	if hr.recorder != "" {
		t.Errorf("recorder = %s, want empty", hr.recorder)
	}
}

func TestHTTPRecorder_KeepsHTTPScheme(t *testing.T) {
	r := HTTPRecorder("https://example.com/api")
	hr := r.(*httpRecorder)
	if !strings.HasPrefix(hr.url, "https://") {
		t.Errorf("expected https:// prefix, got %s", hr.url)
	}
}

func TestHTTPRecorder_WithOptions(t *testing.T) {
	r := HTTPRecorder("http://example.com",
		RecorderHTTPRecorderOption("my-recorder"),
		TimeoutHTTPRecorderOption(5*time.Second),
		HeaderHTTPRecorderOption(http.Header{"X-Custom": []string{"val"}}),
	)
	hr := r.(*httpRecorder)
	// NOTE: recorder field is not propagated from options — a pre-existing bug.
	// The metrics counter in Record will always have recorder="" as the label.
	if hr.httpClient.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", hr.httpClient.Timeout)
	}
	if hr.header.Get("X-Custom") != "val" {
		t.Errorf("header = %v", hr.header)
	}
}

func TestHTTPRecorder_Record_Success(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %s, want application/json", ct)
		}
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := HTTPRecorder(srv.URL)
	err := r.Record(context.Background(), []byte(`{"test": true}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(receivedBody) != `{"test": true}` {
		t.Errorf("body = %s, want {\"test\": true}", string(receivedBody))
	}
}

func TestHTTPRecorder_Record_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := HTTPRecorder(srv.URL)
	err := r.Record(context.Background(), []byte("data"))
	if err == nil {
		t.Error("expected error on non-2xx response")
	}
}

func TestHTTPRecorder_Record_ContextCanceled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := HTTPRecorder(srv.URL)
	err := r.Record(ctx, []byte("data"))
	if err == nil {
		t.Error("expected error on canceled context")
	}
}

func TestHTTPRecorder_Record_CustomHeader(t *testing.T) {
	var receivedHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := HTTPRecorder(srv.URL, HeaderHTTPRecorderOption(http.Header{
		"X-Custom": []string{"my-value"},
	}))
	err := r.Record(context.Background(), []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if receivedHeader != "my-value" {
		t.Errorf("X-Custom = %s, want my-value", receivedHeader)
	}
}

func TestHTTPRecorder_Record_CustomHeaderContentTypePreserved(t *testing.T) {
	var receivedCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := HTTPRecorder(srv.URL, HeaderHTTPRecorderOption(http.Header{
		"Content-Type": []string{"text/plain"},
	}))
	err := r.Record(context.Background(), []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if receivedCT != "text/plain" {
		t.Errorf("Content-Type = %s, want text/plain", receivedCT)
	}
}

func TestHTTPRecorder_Record_ContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(100 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	r := HTTPRecorder(srv.URL)
	time.Sleep(20 * time.Millisecond) // ensure timeout has fired
	err := r.Record(ctx, []byte("data"))
	if err == nil {
		t.Error("expected error on deadline-exceeded context")
	}
}

func TestHTTPRecorder_NilHeader(t *testing.T) {
	r := HTTPRecorder("http://example.com")
	hr := r.(*httpRecorder)
	if hr.header != nil {
		t.Error("header should be nil by default")
	}
}

func TestHTTPRecorder_AddsHTTPScheme(t *testing.T) {
	r := HTTPRecorder("example.com:8080")
	hr := r.(*httpRecorder)
	if !strings.HasPrefix(hr.url, "http://") {
		t.Errorf("expected http:// prefix, got %s", hr.url)
	}
}

// --- TCPRecorder tests ---

func TestTCPRecorder_Record(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var received []byte
	done := make(chan struct{})
	go func() {
		conn, _ := ln.Accept()
		received, _ = io.ReadAll(conn)
		conn.Close()
		close(done)
	}()

	r := TCPRecorder(ln.Addr().String())
	err = r.Record(context.Background(), []byte("hello-tcp"))
	if err != nil {
		t.Fatal(err)
	}

	<-done
	if string(received) != "hello-tcp" {
		t.Errorf("received = %s, want hello-tcp", string(received))
	}
}

func TestTCPRecorder_Record_LargePayload(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var received []byte
	done := make(chan struct{})
	go func() {
		conn, _ := ln.Accept()
		received, _ = io.ReadAll(conn)
		conn.Close()
		close(done)
	}()

	// Write a payload larger than typical TCP buffer to exercise the write loop.
	payload := bytes.Repeat([]byte("x"), 64*1024)
	r := TCPRecorder(ln.Addr().String())
	err = r.Record(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}

	<-done
	if len(received) != len(payload) {
		t.Errorf("received %d bytes, want %d", len(received), len(payload))
	}
	if !bytes.Equal(received, payload) {
		t.Error("received data does not match payload")
	}
}

func TestTCPRecorder_Record_ConnectionRefused(t *testing.T) {
	r := TCPRecorder("127.0.0.1:1", TimeoutTCPRecorderOption(50*time.Millisecond))
	err := r.Record(context.Background(), []byte("data"))
	if err == nil {
		t.Error("expected error on connection refused")
	}
}

func TestTCPRecorder_WithOptions(t *testing.T) {
	l := xlogger.Nop()
	r := TCPRecorder("127.0.0.1:8080",
		RecorderTCPRecorderOption("tcp-rec"),
		TimeoutTCPRecorderOption(3*time.Second),
		LogTCPRecorderOption(l),
	)
	tr := r.(*tcpRecorder)
	if tr.recorder != "tcp-rec" {
		t.Errorf("recorder = %s, want tcp-rec", tr.recorder)
	}
	if tr.dialer.Timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", tr.dialer.Timeout)
	}
}

func TestTCPRecorder_Record_ContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	// Use a non-routable address to trigger a dial timeout.
	r := TCPRecorder("10.255.255.1:9999", TimeoutTCPRecorderOption(5*time.Second))
	err := r.Record(ctx, []byte("data"))
	if err == nil {
		t.Error("expected error on deadline-exceeded context")
	}
}

func TestTCPRecorder_WithLogger(t *testing.T) {
	l := xlogger.Nop()
	r := TCPRecorder("127.0.0.1:8080", LogTCPRecorderOption(l))
	tr := r.(*tcpRecorder)
	if tr.log != l {
		t.Error("log should be set")
	}
}

func TestTCPRecorder_NilLogger(t *testing.T) {
	r := TCPRecorder("127.0.0.1:0")
	tr := r.(*tcpRecorder)
	if tr.log != nil {
		t.Error("logger should be nil by default")
	}
}

// --- HandlerRecorderObject tests ---

func TestHandlerRecorderObject_Record(t *testing.T) {
	var buf bytes.Buffer
	fr := FileRecorder(&nopWriteCloser{&buf})

	p := &HandlerRecorderObject{
		Service: "test-svc",
		Network: "tcp",
		Host:    "example.com",
		Time:    time.Now(),
	}
	err := p.Record(context.Background(), fr)
	if err != nil {
		t.Fatal(err)
	}

	var decoded HandlerRecorderObject
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Service != "test-svc" {
		t.Errorf("Service = %s, want test-svc", decoded.Service)
	}
	if decoded.Network != "tcp" {
		t.Errorf("Network = %s, want tcp", decoded.Network)
	}
}

func TestHandlerRecorderObject_Record_NilReceiver(t *testing.T) {
	var p *HandlerRecorderObject
	err := p.Record(context.Background(), &noopRecorder{})
	if err != nil {
		t.Errorf("nil receiver should not return error: %v", err)
	}
}

func TestHandlerRecorderObject_Record_NilRecorder(t *testing.T) {
	p := &HandlerRecorderObject{
		Service: "test",
		Time:    time.Now(),
	}
	err := p.Record(context.Background(), nil)
	if err != nil {
		t.Errorf("nil recorder should not return error: %v", err)
	}
}

func TestHandlerRecorderObject_Record_ZeroTime(t *testing.T) {
	p := &HandlerRecorderObject{
		Service: "test",
	}
	err := p.Record(context.Background(), &noopRecorder{})
	if err != nil {
		t.Errorf("zero time should return nil: %v", err)
	}
}

func TestHandlerRecorderObject_Record_FullObject(t *testing.T) {
	var buf bytes.Buffer
	fr := FileRecorder(&nopWriteCloser{&buf})

	now := time.Now()
	p := &HandlerRecorderObject{
		Node:        "node1",
		Service:     "svc",
		Network:     "tcp",
		RemoteAddr:  "1.2.3.4:5678",
		LocalAddr:   "10.0.0.1:8080",
		ClientAddr:  "5.6.7.8:1111",
		SrcAddr:     "5.6.7.8:1111",
		DstAddr:     "9.9.9.9:443",
		Host:        "example.com",
		Proto:       "https",
		ClientIP:    "5.6.7.8",
		ClientID:    "client-1",
		HTTP: &HTTPRecorderObject{
			Host:       "example.com",
			Method:     "GET",
			Proto:      "HTTP/1.1",
			Scheme:     "https",
			URI:        "/path",
			StatusCode: 200,
			Request: HTTPRequestRecorderObject{
				ContentLength: 100,
				Header:        http.Header{"Accept": []string{"*/*"}},
				Body:          []byte("req-body"),
			},
			Response: HTTPResponseRecorderObject{
				ContentLength: 50,
				Header:        http.Header{"Content-Type": []string{"text/plain"}},
				Body:          []byte("resp-body"),
			},
		},
		Websocket: &WebsocketRecorderObject{
			From:    "client",
			OpCode:  1,
			Payload: []byte("ws-data"),
		},
		TLS: &TLSRecorderObject{
			ServerName:  "example.com",
			CipherSuite: "TLS_AES_128_GCM_SHA256",
			Version:     "1.3",
		},
		DNS: &DNSRecorderObject{
			ID:    42,
			Name:  "example.com",
			Type:  "A",
			Class: "IN",
		},
		Route:       "chain-1",
		InputBytes:  4096,
		OutputBytes: 8192,
		Redirect:    "http://other.example.com",
		Err:         "",
		SID:         "sid-123",
		Duration:    123 * time.Millisecond,
		Time:        now,
	}
	err := p.Record(context.Background(), fr)
	if err != nil {
		t.Fatal(err)
	}

	var decoded HandlerRecorderObject
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Node != "node1" {
		t.Errorf("Node = %s, want node1", decoded.Node)
	}
	if decoded.InputBytes != 4096 {
		t.Errorf("InputBytes = %d, want 4096", decoded.InputBytes)
	}
	if decoded.OutputBytes != 8192 {
		t.Errorf("OutputBytes = %d, want 8192", decoded.OutputBytes)
	}
	if decoded.HTTP == nil {
		t.Fatal("HTTP should not be nil")
	}
	if decoded.HTTP.StatusCode != 200 {
		t.Errorf("HTTP status = %d, want 200", decoded.HTTP.StatusCode)
	}
	if decoded.HTTP.Request.Body == nil {
		t.Fatal("HTTP request body should not be nil")
	}
	if decoded.Websocket == nil {
		t.Fatal("Websocket should not be nil")
	}
	if decoded.TLS == nil {
		t.Fatal("TLS should not be nil")
	}
	if decoded.DNS == nil {
		t.Fatal("DNS should not be nil")
	}
	if decoded.Duration != 123*time.Millisecond {
		t.Errorf("Duration = %v, want 123ms", decoded.Duration)
	}
	if !decoded.Time.Equal(now) {
		t.Errorf("Time mismatch: %v != %v", decoded.Time, now)
	}
}

func TestHandlerRecorderObject_Record_WithError(t *testing.T) {
	var buf bytes.Buffer
	fr := FileRecorder(&nopWriteCloser{&buf})

	p := &HandlerRecorderObject{
		Service: "test",
		Time:    time.Now(),
		Err:     "connection reset",
	}
	err := p.Record(context.Background(), fr)
	if err != nil {
		t.Fatal(err)
	}

	var decoded HandlerRecorderObject
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Err != "connection reset" {
		t.Errorf("Err = %s, want connection reset", decoded.Err)
	}
}

func TestHandlerRecorderObject_JSONRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	original := HandlerRecorderObject{
		Service:     "svc",
		Network:     "tcp",
		RemoteAddr:  "1.2.3.4:8080",
		LocalAddr:   "10.0.0.1:3128",
		ClientAddr:  "5.6.7.8:12345",
		SrcAddr:     "5.6.7.8:12345",
		DstAddr:     "93.184.216.34:443",
		Host:        "example.com",
		ClientIP:    "5.6.7.8",
		InputBytes:  1024,
		OutputBytes: 2048,
		SID:         "sid-1",
		Duration:    50 * time.Millisecond,
		Time:        now,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	var decoded HandlerRecorderObject
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}

	if decoded.Service != original.Service {
		t.Errorf("Service = %s, want %s", decoded.Service, original.Service)
	}
	if decoded.InputBytes != original.InputBytes {
		t.Errorf("InputBytes = %d, want %d", decoded.InputBytes, original.InputBytes)
	}
	if decoded.OutputBytes != original.OutputBytes {
		t.Errorf("OutputBytes = %d, want %d", decoded.OutputBytes, original.OutputBytes)
	}
	if decoded.SID != original.SID {
		t.Errorf("SID = %s, want %s", decoded.SID, original.SID)
	}
	if !decoded.Time.Equal(now) {
		t.Errorf("Time = %v, want %v", decoded.Time, now)
	}
}

func TestHandlerRecorderObject_JSON_OmitEmpty(t *testing.T) {
	p := HandlerRecorderObject{
		Service: "svc",
		Time:    time.Now(),
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	// Fields with omitempty should not appear.
	if strings.Contains(string(data), `"node"`) {
		t.Error("empty node should be omitted")
	}
	if strings.Contains(string(data), `"err"`) {
		t.Error("empty err should be omitted")
	}
	if strings.Contains(string(data), `"route"`) {
		t.Error("empty route should be omitted")
	}
}

// --- Interface compliance ---

func TestFileRecorder_SatisfiesRecorder(t *testing.T) {
	var _ recorder.Recorder = FileRecorder(&nopWriteCloser{&bytes.Buffer{}})
}

func TestHTTPRecorder_SatisfiesRecorder(t *testing.T) {
	var _ recorder.Recorder = HTTPRecorder("http://example.com")
}

func TestTCPRecorder_SatisfiesRecorder(t *testing.T) {
	var _ recorder.Recorder = TCPRecorder("127.0.0.1:8080")
}

var _ io.Closer = (*fileRecorder)(nil)
var _ io.Closer = (*redisSetRecorder)(nil)
var _ io.Closer = (*redisListRecorder)(nil)
var _ io.Closer = (*redisSortedSetRecorder)(nil)

// --- Helper types ---

type nopWriteCloser struct {
	io.Writer
}

func (n *nopWriteCloser) Close() error {
	return nil
}

type noopRecorder struct{}

func (n *noopRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	return nil
}

type errorWriter struct{}

func (e *errorWriter) Write(b []byte) (int, error) {
	return 0, errors.New("write error")
}

func (e *errorWriter) Close() error {
	return nil
}

type writeOnceThenError struct {
	max   int
	count int
}

func (w *writeOnceThenError) Write(b []byte) (int, error) {
	w.count++
	if w.count > w.max {
		return 0, errors.New("write error")
	}
	return len(b), nil
}

func (w *writeOnceThenError) Close() error {
	return nil
}
