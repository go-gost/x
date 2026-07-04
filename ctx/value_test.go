package ctx

import (
	"context"
	"net"
	"reflect"
	"testing"
)

func TestContextWithSrcAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080}
	ctx := ContextWithSrcAddr(context.Background(), addr)

	got := SrcAddrFromContext(ctx)
	if got != addr {
		t.Errorf("SrcAddrFromContext() = %v, want %v", got, addr)
	}
}

func TestSrcAddrFromContext_Empty(t *testing.T) {
	if got := SrcAddrFromContext(context.Background()); got != nil {
		t.Errorf("SrcAddrFromContext(empty) = %v, want nil", got)
	}
}

func TestSrcAddrFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), srcAddrKey{}, "not-an-addr")
	if got := SrcAddrFromContext(ctx); got != nil {
		t.Errorf("SrcAddrFromContext(wrong type) = %v, want nil", got)
	}
}

func TestSrcAddrFromContext_NilAddr(t *testing.T) {
	ctx := ContextWithSrcAddr(context.Background(), nil)
	if got := SrcAddrFromContext(ctx); got != nil {
		t.Errorf("SrcAddrFromContext(nil addr) = %v, want nil", got)
	}
}

func TestContextWithDstAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 443}
	ctx := ContextWithDstAddr(context.Background(), addr)

	got := DstAddrFromContext(ctx)
	if got != addr {
		t.Errorf("DstAddrFromContext() = %v, want %v", got, addr)
	}
}

func TestDstAddrFromContext_Empty(t *testing.T) {
	if got := DstAddrFromContext(context.Background()); got != nil {
		t.Errorf("DstAddrFromContext(empty) = %v, want nil", got)
	}
}

func TestDstAddrFromContext_NilAddr(t *testing.T) {
	ctx := ContextWithDstAddr(context.Background(), nil)
	if got := DstAddrFromContext(ctx); got != nil {
		t.Errorf("DstAddrFromContext(nil addr) = %v, want nil", got)
	}
}

func TestSid_String(t *testing.T) {
	sid := Sid("session-123")
	if s := sid.String(); s != "session-123" {
		t.Errorf("Sid.String() = %q, want %q", s, "session-123")
	}
}

func TestContextWithSid(t *testing.T) {
	sid := Sid("abc-123")
	ctx := ContextWithSid(context.Background(), sid)

	got := SidFromContext(ctx)
	if got != sid {
		t.Errorf("SidFromContext() = %v, want %v", got, sid)
	}
}

func TestSidFromContext_Empty(t *testing.T) {
	if got := SidFromContext(context.Background()); got != "" {
		t.Errorf("SidFromContext(empty) = %q, want empty string", got)
	}
}

func TestSidFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), sidKey{}, 42)
	if got := SidFromContext(ctx); got != "" {
		t.Errorf("SidFromContext(wrong type) = %q, want empty string", got)
	}
}

func TestContextWithHash(t *testing.T) {
	h := &Hash{Source: "client-ip"}
	ctx := ContextWithHash(context.Background(), h)

	got := HashFromContext(ctx)
	if got != h {
		t.Errorf("HashFromContext() = %v, want %v", got, h)
	}
}

func TestHashFromContext_Empty(t *testing.T) {
	if got := HashFromContext(context.Background()); got != nil {
		t.Errorf("HashFromContext(empty) = %v, want nil", got)
	}
}

func TestHashFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), hashKey{}, "not-a-hash")
	if got := HashFromContext(ctx); got != nil {
		t.Errorf("HashFromContext(wrong type) = %v, want nil", got)
	}
}

func TestHashFromContext_NilHash(t *testing.T) {
	ctx := ContextWithHash(context.Background(), nil)
	if got := HashFromContext(ctx); got != nil {
		t.Errorf("HashFromContext(nil hash) = %v, want nil", got)
	}
}

func TestClientID_String(t *testing.T) {
	cid := ClientID("client-456")
	if s := cid.String(); s != "client-456" {
		t.Errorf("ClientID.String() = %q, want %q", s, "client-456")
	}
}

func TestContextWithClientID(t *testing.T) {
	cid := ClientID("user-789")
	ctx := ContextWithClientID(context.Background(), cid)

	got := ClientIDFromContext(ctx)
	if got != cid {
		t.Errorf("ClientIDFromContext() = %v, want %v", got, cid)
	}
}

func TestClientIDFromContext_Empty(t *testing.T) {
	if got := ClientIDFromContext(context.Background()); got != "" {
		t.Errorf("ClientIDFromContext(empty) = %q, want empty string", got)
	}
}

func TestClientIDFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), clientIDKey{}, 99)
	if got := ClientIDFromContext(ctx); got != "" {
		t.Errorf("ClientIDFromContext(wrong type) = %q, want empty string", got)
	}
}

func TestPeerCertContext(t *testing.T) {
	cert := &PeerCert{
		CN:          "client.example.com",
		SANs:        []string{"san1.example.com", "san2.example.com"},
		Fingerprint: "abcdef1234567890",
	}
	ctx := ContextWithPeerCert(context.Background(), cert)

	got := PeerCertFromContext(ctx)
	if got == nil {
		t.Fatal("PeerCertFromContext() = nil, want non-nil")
	}
	if got.CN != cert.CN {
		t.Errorf("PeerCertFromContext().CN = %q, want %q", got.CN, cert.CN)
	}
	if len(got.SANs) != len(cert.SANs) || got.SANs[0] != cert.SANs[0] {
		t.Errorf("PeerCertFromContext().SANs = %v, want %v", got.SANs, cert.SANs)
	}
	if got.Fingerprint != cert.Fingerprint {
		t.Errorf("PeerCertFromContext().Fingerprint = %q, want %q", got.Fingerprint, cert.Fingerprint)
	}
}

func TestPeerCertFromContext_Empty(t *testing.T) {
	if got := PeerCertFromContext(context.Background()); got != nil {
		t.Errorf("PeerCertFromContext(empty) = %v, want nil", got)
	}
}

func TestPeerCertFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), peerCertKey{}, "not-a-cert")
	if got := PeerCertFromContext(ctx); got != nil {
		t.Errorf("PeerCertFromContext(wrong type) = %v, want nil", got)
	}
}

func TestPeerCertFromContext_Nil(t *testing.T) {
	ctx := ContextWithPeerCert(context.Background(), nil)
	if got := PeerCertFromContext(ctx); got != nil {
		t.Errorf("PeerCertFromContext(nil) = %v, want nil", got)
	}
}

func TestContextWithLabels(t *testing.T) {
	labels := map[string]string{"tenant": "acme", "region": "eu"}
	ctx := ContextWithLabels(context.Background(), labels)

	got := LabelsFromContext(ctx)
	if !reflect.DeepEqual(got, labels) {
		t.Errorf("LabelsFromContext() = %v, want %v", got, labels)
	}
}

func TestLabelsFromContext_Empty(t *testing.T) {
	if got := LabelsFromContext(context.Background()); got != nil {
		t.Errorf("LabelsFromContext(empty) = %v, want nil", got)
	}
}

func TestLabelsFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), labelsKey{}, "not-a-map")
	if got := LabelsFromContext(ctx); got != nil {
		t.Errorf("LabelsFromContext(wrong type) = %v, want nil", got)
	}
}

func TestMultipleValuesInContext(t *testing.T) {
	ctx := context.Background()
	ctx = ContextWithSrcAddr(ctx, &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080})
	ctx = ContextWithDstAddr(ctx, &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 443})
	ctx = ContextWithSid(ctx, Sid("multi-session"))
	ctx = ContextWithHash(ctx, &Hash{Source: "hash-src"})
	ctx = ContextWithClientID(ctx, ClientID("multi-client"))

	if got := SrcAddrFromContext(ctx); got == nil {
		t.Error("SrcAddrFromContext() should not be nil")
	}
	if got := DstAddrFromContext(ctx); got == nil {
		t.Error("DstAddrFromContext() should not be nil")
	}
	if got := SidFromContext(ctx); got != "multi-session" {
		t.Errorf("SidFromContext() = %q, want %q", got, "multi-session")
	}
	if got := HashFromContext(ctx); got == nil || got.Source != "hash-src" {
		t.Errorf("HashFromContext().Source = %v, want %q", got, "hash-src")
	}
	if got := ClientIDFromContext(ctx); got != "multi-client" {
		t.Errorf("ClientIDFromContext() = %q, want %q", got, "multi-client")
	}
}

func TestIndependentKeys(t *testing.T) {
	ctx := ContextWithSrcAddr(context.Background(), &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080})

	// Other keys should not be affected.
	if got := SidFromContext(ctx); got != "" {
		t.Errorf("SidFromContext() = %q, want empty after setting SrcAddr", got)
	}
	if got := HashFromContext(ctx); got != nil {
		t.Errorf("HashFromContext() = %v, want nil after setting SrcAddr", got)
	}
}

type testContextConn struct {
	ctx context.Context
}

func (c *testContextConn) Context() context.Context {
	return c.ctx
}

func TestContextInterface(t *testing.T) {
	ctx := context.Background()
	ctx = ContextWithSid(ctx, Sid("iface-test"))

	conn := &testContextConn{ctx: ctx}
	cc, ok := any(conn).(Context)
	if !ok {
		t.Fatal("testContextConn should implement Context interface")
	}

	inner := cc.Context()
	if got := SidFromContext(inner); got != "iface-test" {
		t.Errorf("SidFromContext(inner) = %q, want %q", got, "iface-test")
	}
}
