package http

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/recorder"
	xrecorder "github.com/go-gost/x/recorder"
)

func TestCopyWebsocketFrame_ReadError(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}

	buf := &bytes.Buffer{}
	err := h.copyWebsocketFrame(io.Discard, bytes.NewReader(nil), buf, "client", nil)
	if err == nil {
		t.Error("expected read error from empty reader")
	}
}

func TestCopyWebsocketDirection_ErrorReader(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.recorder = recorder.RecorderObject{}

	errc := make(chan error, 1)

	go h.copyWebsocketDirection(context.Background(), &errorReader{}, io.Discard, "client", nil, 10.0, &testLogger{}, errc)

	err := <-errc
	if err == nil {
		t.Error("expected error from error reader")
	}
}

func TestCopyWebsocketFrame_WithBodyRecording(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.recorder = recorder.RecorderObject{
		Options: &recorder.Options{
			HTTPBody:   true,
			MaxBodySize: 1024,
		},
	}

	// Build a minimal WebSocket text frame (fin=1, opcode=1, payload="hello")
	frame := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}
	buf := &bytes.Buffer{}

	ro := &xrecorder.HandlerRecorderObject{}
	err := h.copyWebsocketFrame(io.Discard, bytes.NewReader(frame), buf, "client", ro)
	if err != nil {
		t.Fatalf("copyWebsocketFrame: %v", err)
	}
	if ro.Websocket == nil {
		t.Fatal("expected Websocket recorder object")
	}
	if ro.Websocket.OpCode != 1 { // text frame
		t.Errorf("got OpCode %d, want 1", ro.Websocket.OpCode)
	}
	if ro.InputBytes == 0 {
		t.Error("expected non-zero InputBytes for client frame")
	}
	if ro.OutputBytes != 0 {
		t.Error("expected zero OutputBytes for client frame")
	}
}

func TestCopyWebsocketFrame_ServerDirection(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.recorder = recorder.RecorderObject{}

	frame := []byte{0x82, 0x03, 'a', 'b', 'c'} // binary frame
	buf := &bytes.Buffer{}

	ro := &xrecorder.HandlerRecorderObject{}
	err := h.copyWebsocketFrame(io.Discard, bytes.NewReader(frame), buf, "server", ro)
	if err != nil {
		t.Fatalf("copyWebsocketFrame: %v", err)
	}
	if ro.InputBytes != 0 {
		t.Error("expected zero InputBytes for server frame")
	}
	if ro.OutputBytes == 0 {
		t.Error("expected non-zero OutputBytes for server frame")
	}
}

func TestCopyWebsocketDirection_NilRO(t *testing.T) {
	h := &httpHandler{
		options: handler.Options{
			Logger: &testLogger{},
		},
	}
	h.recorder = recorder.RecorderObject{}

	errc := make(chan error, 1)
	go h.copyWebsocketDirection(context.Background(), &errorReader{}, io.Discard, "client", nil, 10.0, &testLogger{}, errc)
	<-errc
}

// errorReader always returns an error.
type errorReader struct{}

func (r *errorReader) Read(p []byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (r *errorReader) Write(p []byte) (int, error) { return len(p), nil }
func (r *errorReader) Close() error                { return nil }
