package relay

import (
	"bytes"
	"io"
	"testing"
)

func TestTCPConn_WriteWithCachedHeader(t *testing.T) {
	var underlying bytes.Buffer
	tc := &tcpConn{
		Conn: &fakeConn{}, // embedded net.Conn — just for Read
	}
	// Simulate a cached header
	tc.wbuf.Write([]byte("HEADER "))

	n, err := tc.Write([]byte("data"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 4 {
		t.Errorf("n = %d, want 4", n)
	}

	// The wbuf was flushed: header + data
	combined := tc.wbuf.Bytes()
	if len(combined) != 0 {
		t.Errorf("wbuf should be empty after flush, got %d bytes", len(combined))
	}

	// tcpConn has no underlying writeBuf — writes go to the embedded conn
	_ = underlying
	_ = tc.Conn
}

func TestTCPConn_WriteWithoutCachedHeader(t *testing.T) {
	// Nothing special to test — writes delegate to Conn.Write
	// Just verify no panic and returns correctly
	tc := &tcpConn{Conn: &fakeConn{}}
	n, err := tc.Write([]byte("data"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 4 {
		t.Errorf("n = %d, want 4", n)
	}
}

func TestTCPConn_ReadDelegates(t *testing.T) {
	buf := []byte("hello world")
	fc := &fakeConn{buf: buf}
	tc := &tcpConn{Conn: fc}

	out := make([]byte, 5)
	n, err := tc.Read(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 || string(out[:n]) != "hello" {
		t.Errorf("Read = %q, want %q", string(out[:n]), "hello")
	}
}

func TestUDPConn_ReadWithLengthPrefix(t *testing.T) {
	// udpConn.Read expects [2-byte length][data]
	payload := []byte("hello")
	prefixed := make([]byte, 2+len(payload))
	prefixed[0] = 0
	prefixed[1] = byte(len(payload))
	copy(prefixed[2:], payload)

	fc := &fakeConn{buf: prefixed}
	uc := &udpConn{Conn: fc}

	out := make([]byte, 10)
	n, err := uc.Read(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
	if string(out[:n]) != "hello" {
		t.Errorf("Read = %q, want %q", string(out[:n]), "hello")
	}
}

func TestUDPConn_ReadTruncated(t *testing.T) {
	// When the read buffer is smaller than the UDP payload
	payload := []byte("hello world")
	prefixed := make([]byte, 2+len(payload))
	prefixed[0] = 0
	prefixed[1] = byte(len(payload))
	copy(prefixed[2:], payload)

	fc := &fakeConn{buf: prefixed}
	uc := &udpConn{Conn: fc}

	// Read with a small buffer
	out := make([]byte, 5)
	n, err := uc.Read(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
	if string(out[:n]) != "hello" {
		t.Errorf("Read = %q, want %q", string(out[:n]), "hello")
	}
}

func TestUDPConn_WriteWithCachedHeader(t *testing.T) {
	fc := &fakeConn{}
	uc := &udpConn{Conn: fc}
	// Simulate a cached header (e.g., the relay response)
	uc.wbuf.Write([]byte("HEADER "))

	n, err := uc.Write([]byte("hi"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 2 {
		t.Errorf("n = %d, want 2", n)
	}

	// Verify the wbuf was flushed
	if uc.wbuf.Len() > 0 {
		t.Errorf("wbuf should be empty after flush, got %d bytes", uc.wbuf.Len())
	}

	// The header + [2-byte length] + "hi" should be written to fc
	written := fc.writeBuf.Bytes()
	if len(written) == 0 {
		t.Fatal("nothing written to underlying conn")
	}
	// Should contain: "HEADER " + length prefix + "hi"
	expected := []byte("HEADER ")
	expected = append(expected, 0x00, 0x02) // length prefix
	expected = append(expected, 'h', 'i')
	if !bytes.Equal(written, expected) {
		t.Errorf("written = %v, want %v", written, expected)
	}
}

func TestUDPConn_WriteWithoutCachedHeader(t *testing.T) {
	fc := &fakeConn{}
	uc := &udpConn{Conn: fc}

	n, err := uc.Write([]byte("hi"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 2 {
		t.Errorf("n = %d, want 2", n)
	}

	// Should write [2-byte length] + "hi"
	written := fc.writeBuf.Bytes()
	if len(written) < 2 {
		t.Fatal("nothing written to underlying conn")
	}
	if written[0] != 0 || written[1] != 2 {
		t.Errorf("length prefix = %v, want [0, 2]", written[:2])
	}
	if string(written[2:]) != "hi" {
		t.Errorf("data = %q, want %q", string(written[2:]), "hi")
	}
}

func TestUDPConn_WriteExceedsMaxLength(t *testing.T) {
	fc := &fakeConn{}
	uc := &udpConn{Conn: fc}

	// Write more than MaxUint16 bytes
	data := make([]byte, 65536)
	_, err := uc.Write(data)
	if err == nil {
		t.Error("expected error for data > 65535 bytes")
	}
}

func TestTCPConn_WriteWithCachedHeaderAndFlush(t *testing.T) {
	fc := &fakeConn{}
	tc := &tcpConn{Conn: fc}
	tc.wbuf.Write([]byte("RESPONSE "))

	n, err := tc.Write([]byte("body"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 4 {
		t.Errorf("n = %d, want 4", n)
	}

	// wbuf should be empty after flush
	if tc.wbuf.Len() > 0 {
		t.Errorf("wbuf should be empty, got %d bytes", tc.wbuf.Len())
	}

	// The conn should have: "RESPONSE body"
	written := fc.writeBuf.Bytes()
	if string(written) != "RESPONSE body" {
		t.Errorf("written = %q, want %q", string(written), "RESPONSE body")
	}
}

func TestUDPConn_ReadEmpty(t *testing.T) {
	// Read on an empty connection should return io.EOF
	fc := &fakeConn{} // no buf
	uc := &udpConn{Conn: fc}

	_, err := uc.Read(make([]byte, 10))
	if err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestUDPConn_ReadPartial(t *testing.T) {
	// Length says 10 bytes but only 3 are available
	prefixed := []byte{0x00, 0x0A, 'a', 'b', 'c'}
	fc := &fakeConn{buf: prefixed}
	uc := &udpConn{Conn: fc}

	_, err := uc.Read(make([]byte, 10))
	if err == nil {
		t.Error("expected error for truncated data")
	}
}