package http

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/recorder"
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

// errorReader always returns an error.
type errorReader struct{}

func (r *errorReader) Read(p []byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (r *errorReader) Write(p []byte) (int, error) { return len(p), nil }
func (r *errorReader) Close() error                { return nil }
