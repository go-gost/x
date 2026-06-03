package router

import (
	"bytes"
	"io"
	"testing"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	"github.com/google/uuid"
)

// init sets up the default logger to prevent nil panics in NewConnector.
func init() {
	logger.SetDefault(&testLogger{})
}

// ---------------------------------------------------------------------------
// CloseWriter — helper that tracks close calls
// ---------------------------------------------------------------------------

type closeWriter struct {
	closeFn func() error
}

func (w *closeWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *closeWriter) Close() error {
	if w.closeFn != nil {
		return w.closeFn()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Connector tests
// ---------------------------------------------------------------------------

func TestNewConnector_Minimal(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	cid := relay.NewConnectorID([]byte("abcdef0123456789"))
	c := NewConnector(rid, cid, "example.com", nil, nil)
	if c == nil {
		t.Fatal("connector is nil")
	}
	if !c.ID().Equal(cid) {
		t.Errorf("ID = %v, want %v", c.ID(), cid)
	}
	if w := c.Writer(); w != nil {
		t.Errorf("Writer = %v, want nil", w)
	}
}

func TestNewConnector_WithOpts(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	cid := relay.NewConnectorID([]byte("abcdef0123456789"))
	var buf bytes.Buffer
	c := NewConnector(rid, cid, "example.com", &buf, &ConnectorOptions{})
	if c == nil {
		t.Fatal("connector is nil")
	}
	n, err := c.Writer().Write([]byte("hello"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
	if buf.String() != "hello" {
		t.Errorf("buf = %q, want hello", buf.String())
	}
}

func TestConnector_Close_NilWriter(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	cid := relay.NewConnectorID([]byte("abcdef0123456789"))
	c := NewConnector(rid, cid, "example.com", nil, nil)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestConnector_Close_Writer(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	cid := relay.NewConnectorID([]byte("abcdef0123456789"))
	closed := false
	c := NewConnector(rid, cid, "example.com", &closeWriter{
		closeFn: func() error { closed = true; return nil },
	}, nil)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !closed {
		t.Error("writer was not closed")
	}
}

func TestConnector_Close_Double(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	cid := relay.NewConnectorID([]byte("abcdef0123456789"))
	c := NewConnector(rid, cid, "example.com", &closeWriter{}, nil)
	c.Close()
	c.Close() // second close should be safe
}

func TestConnector_Writer_Nil(t *testing.T) {
	var c *Connector
	if w := c.Writer(); w != nil {
		t.Errorf("nil connector Writer = %v, want nil", w)
	}
}

func TestConnector_Close_Nil(t *testing.T) {
	var c *Connector
	if err := c.Close(); err != nil {
		t.Fatalf("nil connector Close: %v", err)
	}
}

func TestConnector_Close_NonCloser(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	cid := relay.NewConnectorID([]byte("abcdef0123456789"))
	// bytes.Buffer does not implement io.Closer
	var buf bytes.Buffer
	c := NewConnector(rid, cid, "example.com", &buf, nil)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// xcloseWriter implements io.Closer but times out
type xcloseWriter struct {
	data []byte
}

func (w *xcloseWriter) Write(p []byte) (int, error) {
	w.data = append(w.data, p...)
	return len(p), nil
}
func (w *xcloseWriter) Close() error { return io.ErrClosedPipe }

func TestConnector_Close_CloserError(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	cid := relay.NewConnectorID([]byte("abcdef0123456789"))
	c := NewConnector(rid, cid, "example.com", &xcloseWriter{}, nil)
	if err := c.Close(); err != io.ErrClosedPipe {
		t.Errorf("Close = %v, want ErrClosedPipe", err)
	}
}

// ---------------------------------------------------------------------------
// Router tests
// ---------------------------------------------------------------------------

func TestRouter_AddConnector_Nil(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)
	r.AddConnector(nil) // should not panic
}

func TestRouter_AddGetConnector_Single(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)
	if !r.ID().Equal(rid) {
		t.Errorf("ID = %v, want %v", r.ID(), rid)
	}

	cid := relay.NewConnectorID([]byte("abcdef0123456789"))
	c := NewConnector(rid, cid, "host1", nil, nil)
	r.AddConnector(c)

	got := r.GetConnector("host1")
	if got == nil {
		t.Fatal("GetConnector returned nil")
	}
	if !got.ID().Equal(cid) {
		t.Errorf("ID = %v, want %v", got.ID(), cid)
	}
}

func TestRouter_AddGetConnector_MultipleHosts(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)

	cid1 := relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa"))
	cid2 := relay.NewConnectorID([]byte("bbbbbbbbbbbbbbbb"))
	r.AddConnector(NewConnector(rid, cid1, "host1", nil, nil))
	r.AddConnector(NewConnector(rid, cid2, "host2", nil, nil))

	got1 := r.GetConnector("host1")
	if got1 == nil || !got1.ID().Equal(cid1) {
		t.Errorf("host1 got ID = %v, want %v", got1, cid1)
	}
	got2 := r.GetConnector("host2")
	if got2 == nil || !got2.ID().Equal(cid2) {
		t.Errorf("host2 got ID = %v, want %v", got2, cid2)
	}
}

func TestRouter_GetConnector_EmptyHost(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)
	if got := r.GetConnector(""); got != nil {
		t.Errorf("GetConnector('') = %v, want nil", got)
	}
}

func TestRouter_GetConnector_MissingHost(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)
	if got := r.GetConnector("nonexistent"); got != nil {
		t.Errorf("GetConnector('nonexistent') = %v, want nil", got)
	}
}

func TestRouter_GetConnector_Weighted(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)

	cid1 := relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa"))
	cid2 := relay.NewConnectorID([]byte("bbbbbbbbbbbbbbbb"))
	// Weight 0 should be treated as 1
	r.AddConnector(NewConnector(rid, cid1, "host1", nil, nil))
	r.AddConnector(NewConnector(rid, cid2, "host1", nil, nil))

	// With multiple connectors weighted selection should return non-nil
	got := r.GetConnector("host1")
	if got == nil {
		t.Fatal("GetConnector returned nil for weighted selection")
	}
}

func TestRouter_DelConnector(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)

	cid1 := relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa"))
	cid2 := relay.NewConnectorID([]byte("bbbbbbbbbbbbbbbb"))
	r.AddConnector(NewConnector(rid, cid1, "host1", nil, nil))
	r.AddConnector(NewConnector(rid, cid2, "host1", nil, nil))

	r.DelConnector("host1", cid1)
	got := r.GetConnector("host1")
	if got == nil {
		t.Fatal("GetConnector returned nil after delete")
	}
	if !got.ID().Equal(cid2) {
		t.Errorf("remaining connector = %v, want %v", got.ID(), cid2)
	}
}

func TestRouter_DelConnector_MultipleRemaining(t *testing.T) {
	// Regression test: deleting one of three should leave two intact
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)

	ids := make([]relay.ConnectorID, 3)
	for i := range ids {
		uid := uuid.New()
		ids[i] = relay.NewConnectorID(uid[:])
		r.AddConnector(NewConnector(rid, ids[i], "host1", nil, nil))
	}

	r.DelConnector("host1", ids[0])
	got := r.GetConnector("host1")
	if got == nil {
		t.Fatal("GetConnector returned nil after deleting one of three")
	}
}

func TestRouter_DelConnector_NoMatch(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)

	cid1 := relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa"))
	cid2 := relay.NewConnectorID([]byte("cccccccccccccccc"))
	r.AddConnector(NewConnector(rid, cid1, "host1", nil, nil))

	// Delete with non-existent cid — should be no-op
	r.DelConnector("host1", cid2)
	got := r.GetConnector("host1")
	if got == nil {
		t.Fatal("GetConnector returned nil after deleting non-existent cid")
	}
	if !got.ID().Equal(cid1) {
		t.Errorf("remaining connector = %v, want %v", got.ID(), cid1)
	}
}

func TestRouter_DelConnector_WrongHost(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)

	cid1 := relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa"))
	r.AddConnector(NewConnector(rid, cid1, "host1", nil, nil))

	// Delete with correct cid but wrong host — should be no-op
	r.DelConnector("other-host", cid1)
	got := r.GetConnector("host1")
	if got == nil {
		t.Fatal("GetConnector returned nil after delete with wrong host")
	}
}

func TestRouter_Close(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)
	r.AddConnector(NewConnector(rid, relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa")), "host1", nil, nil))

	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := r.GetConnector("host1"); got != nil {
		t.Error("GetConnector returned non-nil after Close")
	}
}

func TestRouter_Close_Double(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)
	r.Close()
	r.Close() // second close should not panic
}

func TestRouter_Close_ClosesConnectors(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)

	closed := false
	c := NewConnector(rid, relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa")), "host1", &closeWriter{
		closeFn: func() error { closed = true; return nil },
	}, nil)
	r.AddConnector(c)

	r.Close()
	if !closed {
		t.Error("connector was not closed by Router.Close")
	}
}

func TestRouter_ID(t *testing.T) {
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	r := NewRouter("node1", rid)
	if !r.ID().Equal(rid) {
		t.Errorf("ID = %v, want %v", r.ID(), rid)
	}
}

// ---------------------------------------------------------------------------
// ConnectorPool tests
// ---------------------------------------------------------------------------

func TestConnectorPool_NilSafe_Get(t *testing.T) {
	var p *ConnectorPool
	if got := p.Get(relay.TunnelID{}, "host"); got != nil {
		t.Errorf("nil pool Get = %v, want nil", got)
	}
}

func TestConnectorPool_NilSafe_Del(t *testing.T) {
	var p *ConnectorPool
	p.Del(relay.TunnelID{}, "host", relay.ConnectorID{}) // should not panic
}

func TestConnectorPool_NilSafe_Close(t *testing.T) {
	var p *ConnectorPool
	if err := p.Close(); err != nil {
		t.Fatalf("nil pool Close: %v", err)
	}
}

func TestConnectorPool_AddGet(t *testing.T) {
	p := NewConnectorPool("node1")
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	cid := relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa"))

	c := NewConnector(rid, cid, "host1", nil, nil)
	p.Add(rid, c)

	got := p.Get(rid, "host1")
	if got == nil {
		t.Fatal("Get returned nil")
	}
	if !got.ID().Equal(cid) {
		t.Errorf("ID = %v, want %v", got.ID(), cid)
	}
}

func TestConnectorPool_AddGet_NewRouter(t *testing.T) {
	p := NewConnectorPool("node1")
	rid1 := relay.NewTunnelID([]byte("aaaaaaaaaaaaaaaa"))
	rid2 := relay.NewTunnelID([]byte("bbbbbbbbbbbbbbbb"))

	p.Add(rid1, NewConnector(rid1, relay.NewConnectorID([]byte("1111111111111111")), "host1", nil, nil))
	p.Add(rid2, NewConnector(rid2, relay.NewConnectorID([]byte("2222222222222222")), "host1", nil, nil))

	got1 := p.Get(rid1, "host1")
	got2 := p.Get(rid2, "host1")
	if got1 == nil || got2 == nil {
		t.Fatal("different routers should both return connectors")
	}
}

func TestConnectorPool_Get_MissingRouter(t *testing.T) {
	p := NewConnectorPool("node1")
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	otherRid := relay.NewTunnelID([]byte("ffffffffffffffff"))

	p.Add(rid, NewConnector(rid, relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa")), "host1", nil, nil))

	if got := p.Get(otherRid, "host1"); got != nil {
		t.Error("Get with unknown rid returned non-nil")
	}
}

func TestConnectorPool_Get_MissingHost(t *testing.T) {
	p := NewConnectorPool("node1")
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))

	p.Add(rid, NewConnector(rid, relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa")), "host1", nil, nil))

	if got := p.Get(rid, "other-host"); got != nil {
		t.Error("Get with unknown host returned non-nil")
	}
}

func TestConnectorPool_Del(t *testing.T) {
	p := NewConnectorPool("node1")
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	cid1 := relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa"))
	cid2 := relay.NewConnectorID([]byte("bbbbbbbbbbbbbbbb"))

	p.Add(rid, NewConnector(rid, cid1, "host1", nil, nil))
	p.Add(rid, NewConnector(rid, cid2, "host1", nil, nil))

	p.Del(rid, "host1", cid1)
	got := p.Get(rid, "host1")
	if got == nil || !got.ID().Equal(cid2) {
		t.Errorf("after Del got ID = %v, want %v", got, cid2)
	}
}

func TestConnectorPool_Del_UnknownRouter(t *testing.T) {
	p := NewConnectorPool("node1")
	p.Del(relay.NewTunnelID([]byte("aaaaaaaaaaaaaaaa")), "host1", relay.ConnectorID{}) // no-op, should not panic
}

func TestConnectorPool_Close(t *testing.T) {
	p := NewConnectorPool("node1")
	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	p.Add(rid, NewConnector(rid, relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa")), "host1", nil, nil))

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := p.Get(rid, "host1"); got != nil {
		t.Error("Get returned non-nil after Close")
	}
}

func TestConnectorPool_Close_Double(t *testing.T) {
	p := NewConnectorPool("node1")
	p.Close()
	p.Close() // should not panic
}

// ---------------------------------------------------------------------------
// parseRouterID tests
// ---------------------------------------------------------------------------

func TestParseRouterID_Empty(t *testing.T) {
	rid := parseRouterID("")
	if !rid.Equal(relay.TunnelID{}) {
		t.Errorf("parseRouterID('') = %v, want zero value", rid)
	}
}

func TestParseRouterID_ValidUUID(t *testing.T) {
	uid := uuid.New().String()
	rid := parseRouterID(uid)
	if rid.Equal(relay.TunnelID{}) {
		t.Error("parseRouterID(valid) returned zero value")
	}
}

func TestParseRouterID_Invalid(t *testing.T) {
	rid := parseRouterID("not-a-uuid")
	// Invalid UUID returns zero value (no error returned from function)
	if !rid.Equal(relay.TunnelID{}) {
		t.Errorf("parseRouterID('invalid') = %v, want zero value", rid)
	}
}