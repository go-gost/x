package v5

import (
	"net"
	"testing"

	"github.com/go-gost/gosocks5"
)

type dummyConn struct{ net.Conn }

func TestResolveConn_Metadata(t *testing.T) {
	addr := &gosocks5.Addr{Type: gosocks5.AddrIPv4, Host: "93.184.216.34", Port: 0}
	rc := &resolveConn{Conn: dummyConn{}, resolvedAddr: addr}

	md := rc.Metadata()
	if md == nil {
		t.Fatal("Metadata() returned nil")
	}

	v := md.Get("resolvedAddr")
	if v == nil {
		t.Fatal("resolvedAddr key not present in metadata")
	}

	got, ok := v.(*gosocks5.Addr)
	if !ok {
		t.Fatalf("resolvedAddr is %T, want *gosocks5.Addr", v)
	}
	if got.Host != "93.184.216.34" {
		t.Errorf("Host = %q, want %q", got.Host, "93.184.216.34")
	}
	if got.Type != gosocks5.AddrIPv4 {
		t.Errorf("Type = %d, want %d", got.Type, gosocks5.AddrIPv4)
	}
}

func TestResolveConn_Metadata_NilAddr(t *testing.T) {
	rc := &resolveConn{Conn: dummyConn{}, resolvedAddr: nil}

	md := rc.Metadata()
	v := md.Get("resolvedAddr")
	addr, ok := v.(*gosocks5.Addr)
	if !ok {
		t.Fatalf("resolvedAddr has type %T, want *gosocks5.Addr", v)
	}
	if addr != nil {
		t.Errorf("resolvedAddr = %v, want nil", addr)
	}
}
