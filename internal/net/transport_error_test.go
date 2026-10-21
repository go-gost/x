package net

import (
	"errors"
	"testing"
	"time"
)

// slowErrorReadWriter fails to read after a delay, so that the other
// direction of a transport finishes first.
type slowErrorReadWriter struct {
	mockReadWriter
	delay time.Duration
}

func (m *slowErrorReadWriter) Read(p []byte) (int, error) {
	time.Sleep(m.delay)
	return 0, m.readErr
}

// The error of one direction must not be swallowed when the other
// direction finishes first without an error.
//
// Transport used to return the first result it received, so a direction
// that completed successfully hid the error of the other one.
func TestTransport_ReturnsTheErrorOfTheSlowerDirection(t *testing.T) {
	readErr := errors.New("read failure")
	rw1 := &slowErrorReadWriter{
		mockReadWriter: mockReadWriter{readErr: readErr},
		delay:          50 * time.Millisecond,
	}
	rw2 := &mockReadWriter{data: []byte("from rw2")}

	err := Transport(rw1, rw2)
	if !errors.Is(err, readErr) {
		t.Fatalf("Transport = %v, want %v", err, readErr)
	}
}

// The same in the other direction.
func TestTransport_ReturnsTheErrorOfTheSlowerDirectionReversed(t *testing.T) {
	readErr := errors.New("read failure")
	rw1 := &mockReadWriter{data: []byte("from rw1")}
	rw2 := &slowErrorReadWriter{
		mockReadWriter: mockReadWriter{readErr: readErr},
		delay:          50 * time.Millisecond,
	}

	err := Transport(rw1, rw2)
	if !errors.Is(err, readErr) {
		t.Fatalf("Transport = %v, want %v", err, readErr)
	}
}

// A transport that only hits EOF is not an error.
func TestTransport_EOFOnly(t *testing.T) {
	rw1 := &mockReadWriter{}
	rw2 := &mockReadWriter{}

	if err := Transport(rw1, rw2); err != nil {
		t.Fatalf("Transport = %v, want nil", err)
	}
}
