package router

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/go-gost/relay"
)

func TestHandleEntrypoint_ForwardsToConnector(t *testing.T) {
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
	fpc := newFakePacketConn(laddr)

	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	cid := relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa"))

	var connBuf bytes.Buffer
	c := NewConnector(rid, cid, "10.0.0.1", LockWriter(&connBuf), nil)

	h := newInitdHandler(t)
	h.epConn = fpc
	h.pool.Add(rid, c)

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleEntrypoint(&testLogger{})
	}()

	// Build relay request + packet data
	req := relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdAssociate,
		Features: []relay.Feature{
			&relay.TunnelFeature{ID: rid},
			&relay.AddrFeature{
				AType: relay.AddrDomain,
				Host:  "10.0.0.1",
			},
		},
	}
	var buf bytes.Buffer
	req.WriteTo(&buf)
	packetData := []byte("packet-payload")
	buf.Write(packetData)

	fpc.dataCh <- buf.Bytes()
	fpc.addrCh <- laddr

	// Close to stop the loop, then wait for the goroutine to exit
	// before reading connBuf (avoids race with LockWriter).
	fpc.Close()
	<-errCh

	if connBuf.Len() == 0 {
		t.Error("no data forwarded to connector")
	} else if !bytes.Contains(connBuf.Bytes(), packetData) {
		t.Errorf("connector data = %q, want containing %q", connBuf.Bytes(), packetData)
	}
}

func TestHandleEntrypoint_NonAssociateCmd(t *testing.T) {
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
	fpc := newFakePacketConn(laddr)

	rid := relay.NewTunnelID([]byte("0123456789abcdef"))
	var connBuf bytes.Buffer
	c := NewConnector(rid, relay.NewConnectorID([]byte("aaaaaaaaaaaaaaaa")), "10.0.0.1", LockWriter(&connBuf), nil)

	h := newInitdHandler(t)
	h.epConn = fpc
	h.pool.Add(rid, c)

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleEntrypoint(&testLogger{})
	}()

	// Send request with non-Associate cmd (CmdConnect)
	req := relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdConnect,
		Features: []relay.Feature{
			&relay.TunnelFeature{ID: rid},
		},
	}
	var buf bytes.Buffer
	req.WriteTo(&buf)

	fpc.dataCh <- buf.Bytes()
	fpc.addrCh <- laddr

	// Close to stop the loop, then wait for goroutine to exit.
	fpc.Close()
	<-errCh

	if connBuf.Len() > 0 {
		t.Error("data was forwarded to connector despite non-Associate cmd")
	}
}

func TestHandleEntrypoint_NoMatchingConnector(t *testing.T) {
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
	fpc := newFakePacketConn(laddr)

	rid := relay.NewTunnelID([]byte("0123456789abcdef"))

	h := newInitdHandler(t)
	h.epConn = fpc
	// No connector added to pool

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleEntrypoint(&testLogger{})
	}()

	req := relay.Request{
		Version: relay.Version1,
		Cmd:     relay.CmdAssociate,
		Features: []relay.Feature{
			&relay.TunnelFeature{ID: rid},
			&relay.AddrFeature{
				AType: relay.AddrDomain,
				Host:  "10.0.0.1",
			},
		},
	}
	var buf bytes.Buffer
	req.WriteTo(&buf)

	fpc.dataCh <- buf.Bytes()
	fpc.addrCh <- laddr

	// Should not panic or error, just silently drop.
	fpc.Close()
	<-errCh
}

func TestHandleEntrypoint_ReadError(t *testing.T) {
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
	fpc := newFakePacketConn(laddr)

	h := newInitdHandler(t)
	h.epConn = fpc

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.handleEntrypoint(&testLogger{})
	}()

	// Close the packet conn to trigger ReadFrom error
	fpc.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("expected error from handleEntrypoint after ReadFrom failure")
		}
	case <-time.After(time.Second):
		t.Fatal("handleEntrypoint did not exit after ReadFrom error")
	}
}