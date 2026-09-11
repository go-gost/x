package masque

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// blockingStream is a DatagramStreamer whose ReceiveDatagram blocks until the
// context is done, mirroring the quic-go behaviour that only ctx cancellation
// (not stream close) wakes a pending datagram receive.
type blockingStream struct{}

func (s *blockingStream) SendDatagram(b []byte) error { return nil }

func (s *blockingStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestDatagramConn_CloseUnblocksReadFrom(t *testing.T) {
	pc := newDatagramConn(&blockingStream{}, nil, &net.UDPAddr{}, &net.UDPAddr{})

	done := make(chan error, 1)
	go func() {
		_, _, err := pc.ReadFrom(make([]byte, 64))
		done <- err
	}()

	time.Sleep(20 * time.Millisecond)
	if err := pc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected error from ReadFrom after Close, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not return after Close")
	}
}

func TestDatagramConn_ReadDeadline(t *testing.T) {
	pc := newDatagramConn(&blockingStream{}, nil, &net.UDPAddr{}, &net.UDPAddr{})
	defer pc.Close()

	if err := pc.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	_, _, err := pc.ReadFrom(make([]byte, 64))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
}
