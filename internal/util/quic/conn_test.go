package quic

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

type fakePacketConn struct {
	readFn  func([]byte) (int, net.Addr, error)
	writeFn func([]byte, net.Addr) (int, error)
}

func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) { return f.readFn(b) }
func (f *fakePacketConn) WriteTo(b []byte, a net.Addr) (int, error) { return f.writeFn(b, a) }
func (f *fakePacketConn) Close() error                             { return nil }
func (f *fakePacketConn) LocalAddr() net.Addr                      { return nil }
func (f *fakePacketConn) SetDeadline(t time.Time) error            { return nil }
func (f *fakePacketConn) SetReadDeadline(t time.Time) error        { return nil }
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error       { return nil }

var testKey = bytes.Repeat([]byte("k"), 32)
var testAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}

func TestCipherConnReadFromSkipsInvalidDatagrams(t *testing.T) {
	cc := &cipherConn{key: testKey}
	valid, _ := cc.encrypt([]byte("hello"))

	reads := 0
	base := &fakePacketConn{readFn: func(b []byte) (int, net.Addr, error) {
		reads++
		switch reads {
		case 1:
			return copy(b, "x"), testAddr, nil // short/invalid
		case 2:
			return copy(b, valid), testAddr, nil
		}
		t.Fatal("too many reads")
		return 0, nil, nil
	}}
	cc.PacketConn = base

	buf := make([]byte, 1500)
	n, addr, err := cc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}
	if got := buf[:n]; string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
	if addr != testAddr {
		t.Fatalf("addr = %v, want %v", addr, testAddr)
	}
	if reads != 2 {
		t.Fatalf("expected 2 underlying reads, got %d", reads)
	}
}

func TestCipherConnReadFromPropagatesSocketError(t *testing.T) {
	wantErr := errors.New("socket closed")
	base := &fakePacketConn{readFn: func(b []byte) (int, net.Addr, error) {
		return 0, nil, wantErr
	}}
	cc := &cipherConn{PacketConn: base, key: testKey}

	if _, _, err := cc.ReadFrom(make([]byte, 1500)); !errors.Is(err, wantErr) {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestCipherConnReadFromSurfacesBadKey(t *testing.T) {
	base := &fakePacketConn{readFn: func(b []byte) (int, net.Addr, error) {
		return copy(b, "x"), testAddr, nil
	}}
	cc := &cipherConn{PacketConn: base, key: []byte("short")} // invalid AES key length

	if _, _, err := cc.ReadFrom(make([]byte, 1500)); err == nil {
		t.Fatal("expected key size error, got nil")
	}
}

func TestCipherConnWriteToReturnsPlaintextLength(t *testing.T) {
	base := &fakePacketConn{writeFn: func(b []byte, a net.Addr) (int, error) {
		return len(b), nil
	}}
	cc := &cipherConn{PacketConn: base, key: testKey}

	plain := []byte("hello")
	n, err := cc.WriteTo(plain, testAddr)
	if err != nil {
		t.Fatalf("WriteTo error: %v", err)
	}
	if n != len(plain) {
		t.Fatalf("n = %d, want %d (plaintext length, not encrypted length)", n, len(plain))
	}
}
