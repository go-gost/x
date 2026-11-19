package auto

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/handler"
	xlogger "github.com/go-gost/x/logger"
)

type testAuther struct{}

func (testAuther) Authenticate(context.Context, string, string, ...auth.Option) (string, bool) {
	return "", false
}

func handleTLSRecord(t *testing.T, h *autoHandler) error {
	t.Helper()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(context.Background(), server)
	}()

	// A TLS handshake record header is sufficient for protocol detection.
	// Its empty payload makes the no-auther path fail in ClientHello parsing
	// instead of attempting an external connection.
	if _, err := client.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00}); err != nil {
		t.Fatal(err)
	}
	err := <-errCh

	if _, readErr := client.Read(make([]byte, 1)); !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrClosedPipe) {
		t.Fatalf("client read error after Handle returned = %v, want a closed connection", readErr)
	}

	return err
}

func TestHandleRejectsRawTLSWithAuther(t *testing.T) {
	h := &autoHandler{options: handler.Options{
		Auther: testAuther{},
		Logger: xlogger.Nop(),
	}}

	if err := handleTLSRecord(t, h); !errors.Is(err, ErrRawTLSWithAuther) {
		t.Fatalf("Handle() error = %v, want %v", err, ErrRawTLSWithAuther)
	}
}

func TestHandleAllowsRawTLSWithoutAuther(t *testing.T) {
	h := &autoHandler{options: handler.Options{Logger: xlogger.Nop()}}

	if err := handleTLSRecord(t, h); err == nil || errors.Is(err, ErrRawTLSWithAuther) {
		t.Fatalf("Handle() error = %v, want a ClientHello parsing error", err)
	}
}
