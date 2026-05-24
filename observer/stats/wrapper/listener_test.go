package wrapper

import (
	"net"
	"testing"

	"github.com/go-gost/core/observer/stats"
	ostats "github.com/go-gost/x/observer/stats"
)

type fakeListener struct {
	net.Listener
	acceptConn net.Conn
	acceptErr  error
}

func (l *fakeListener) Accept() (net.Conn, error) {
	if l.acceptErr != nil {
		return nil, l.acceptErr
	}
	return l.acceptConn, nil
}

func (l *fakeListener) Close() error { return nil }

func (l *fakeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
}

func TestWrapListener_Nil(t *testing.T) {
	// nil ln
	if result := WrapListener(nil, ostats.NewStats(false)); result != nil {
		t.Error("WrapListener with nil ln should return nil")
	}
	// nil stats
	fl := &fakeListener{}
	if result := WrapListener(fl, nil); result != fl {
		t.Error("WrapListener with nil stats should return original listener")
	}
	// both nil
	if result := WrapListener(nil, nil); result != nil {
		t.Error("WrapListener with both nil should return nil")
	}
}

func TestWrapListener_Accept_WrapsConn(t *testing.T) {
	st := ostats.NewStats(false)
	fc := &fakeConn{}
	fl := &fakeListener{acceptConn: fc}
	wrapped := WrapListener(fl, st)

	conn, err := wrapped.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if conn == fc {
		t.Error("accepted conn should be wrapped, not the raw conn")
	}
	// The wrapper should track connection count
	if st.Get(stats.KindTotalConns) != 1 {
		t.Errorf("totalConns = %d, want 1 after accept", st.Get(stats.KindTotalConns))
	}
	if st.Get(stats.KindCurrentConns) != 1 {
		t.Errorf("currentConns = %d, want 1 after accept", st.Get(stats.KindCurrentConns))
	}
}

func TestWrapListener_Accept_Error(t *testing.T) {
	st := ostats.NewStats(false)
	fl := &fakeListener{acceptErr: net.ErrClosed}
	wrapped := WrapListener(fl, st)

	_, err := wrapped.Accept()
	if err == nil {
		t.Fatal("expected error on accept")
	}
	// connection counters should not be incremented on error
	if st.Get(stats.KindTotalConns) != 0 {
		t.Errorf("totalConns = %d, want 0 after error", st.Get(stats.KindTotalConns))
	}
}
