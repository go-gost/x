package v5

import (
	"context"
	"net"
	"testing"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/gosocks5"
	xlogger "github.com/go-gost/x/logger"
)

func testLogger() logger.Logger {
	return xlogger.Nop()
}

func TestWriteSocksReply(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	addr := &gosocks5.Addr{Type: gosocks5.AddrIPv4, Host: "127.0.0.1", Port: 9050}

	done := make(chan error, 1)
	go func() {
		done <- writeSocksReply(server, gosocks5.Succeeded, addr)
	}()

	reply, err := gosocks5.ReadReply(client)
	if err != nil {
		t.Fatalf("ReadReply: %v", err)
	}
	if reply.Rep != gosocks5.Succeeded {
		t.Errorf("Rep = %d, want %d", reply.Rep, gosocks5.Succeeded)
	}
	if reply.Addr == nil || reply.Addr.Host != "127.0.0.1" {
		t.Errorf("Addr = %v, want 127.0.0.1", reply.Addr)
	}

	if err := <-done; err != nil {
		t.Errorf("writeSocksReply error: %v", err)
	}
}

func TestWriteSocksReply_CmdUnsupported(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- writeSocksReply(server, gosocks5.CmdUnsupported, nil)
	}()

	reply, err := gosocks5.ReadReply(client)
	if err != nil {
		t.Fatalf("ReadReply: %v", err)
	}
	if reply.Rep != gosocks5.CmdUnsupported {
		t.Errorf("Rep = %d, want %d", reply.Rep, gosocks5.CmdUnsupported)
	}

	if err := <-done; err != nil {
		t.Errorf("writeSocksReply error: %v", err)
	}
}

func TestHandleResolve_TorDisabled(t *testing.T) {
	h := &socks5Handler{
		md: metadata{enableTor: false},
	}
	h.options.Logger = testLogger()

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- h.handleResolve(context.Background(), server, "example.com:0", testLogger())
	}()

	reply, err := gosocks5.ReadReply(client)
	if err != nil {
		t.Fatalf("ReadReply: %v", err)
	}
	if reply.Rep != gosocks5.CmdUnsupported {
		t.Errorf("Rep = %d, want CmdUnsupported (%d)", reply.Rep, gosocks5.CmdUnsupported)
	}

	err = <-done
	if err == nil {
		t.Error("expected error when tor is disabled, got nil")
	}
}

func TestHandleResolvePTR_TorDisabled(t *testing.T) {
	h := &socks5Handler{
		md: metadata{enableTor: false},
	}
	h.options.Logger = testLogger()

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan error, 1)
	go func() {
		done <- h.handleResolvePTR(context.Background(), server, "192.168.1.1:0", testLogger())
	}()

	reply, err := gosocks5.ReadReply(client)
	if err != nil {
		t.Fatalf("ReadReply: %v", err)
	}
	if reply.Rep != gosocks5.CmdUnsupported {
		t.Errorf("Rep = %d, want CmdUnsupported (%d)", reply.Rep, gosocks5.CmdUnsupported)
	}

	err = <-done
	if err == nil {
		t.Error("expected error when tor is disabled, got nil")
	}
}
