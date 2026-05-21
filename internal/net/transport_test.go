package net

import (
	"errors"
	"io"
	"testing"
)

// mockReadWriter implements io.ReadWriter
type mockReadWriter struct {
	data    []byte
	readPos int
	readErr error

	writeBuf []byte
}

func (m *mockReadWriter) Read(p []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	if m.readPos >= len(m.data) {
		return 0, io.EOF
	}
	n := copy(p, m.data[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockReadWriter) Write(p []byte) (int, error) {
	m.writeBuf = append(m.writeBuf, p...)
	return len(p), nil
}

func TestTransport_Normal(t *testing.T) {
	rw1 := &mockReadWriter{data: []byte("from rw1")}
	rw2 := &mockReadWriter{data: []byte("from rw2")}

	done := make(chan struct{}, 2)

	go func() {
		_ = CopyBuffer(rw1, rw2, 1024)
		done <- struct{}{}
	}()
	go func() {
		_ = CopyBuffer(rw2, rw1, 1024)
		done <- struct{}{}
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	// rw2 receives data from rw1
	if string(rw2.writeBuf) != "from rw1" {
		t.Errorf("rw2.writeBuf = %q, want %q", string(rw2.writeBuf), "from rw1")
	}
	// rw1 receives data from rw2
	if string(rw1.writeBuf) != "from rw2" {
		t.Errorf("rw1.writeBuf = %q, want %q", string(rw1.writeBuf), "from rw2")
	}
}

func TestTransport_ReadError(t *testing.T) {
	readErr := errors.New("read failure")
	rw1 := &mockReadWriter{readErr: readErr}
	rw2 := &mockReadWriter{data: []byte("from rw2")}

	err := Transport(rw1, rw2)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestCopyBuffer(t *testing.T) {
	src := &mockReadWriter{data: []byte("test data")}
	dst := &mockReadWriter{}

	err := CopyBuffer(dst, src, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(dst.writeBuf) != "test data" {
		t.Errorf("dst.writeBuf = %q, want %q", string(dst.writeBuf), "test data")
	}
}

func TestCopyBuffer_ReadError(t *testing.T) {
	readErr := errors.New("read failure")
	src := &mockReadWriter{readErr: readErr}
	dst := &mockReadWriter{}

	err := CopyBuffer(dst, src, 1024)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestTransport_EOFIgnored(t *testing.T) {
	// Transport treats io.EOF as non-error.
	// Both goroutines return nil/EOF → Transport should return nil.
	rw1 := &mockReadWriter{data: []byte("data")}
	rw2 := &mockReadWriter{data: []byte("")} // empty data → immediate EOF

	err := Transport(rw1, rw2)
	if err != nil {
		t.Errorf("expected nil (EOF is not an error), got %v", err)
	}
}
