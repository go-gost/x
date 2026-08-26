package tunnel

import (
	"net"
	"testing"

	mdata "github.com/go-gost/core/metadata"
	ictx "github.com/go-gost/x/internal/ctx"
	xmd "github.com/go-gost/x/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

// TestBindConnContext verifies that a bindConn exposes its connection metadata
// (the tunneled hostname) via the xctx.Context interface, so the service accept
// loop forwards it into the handler context for filter.host routing (gost#898).
func TestBindConnContext(t *testing.T) {
	md := mdata.Metadata(xmd.NewMetadata(map[string]any{"host": "example.local:80"}))
	cn := &bindConn{
		Conn:       &net.TCPConn{},
		localAddr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		remoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80},
		md:         md,
	}

	got := mdutil.GetString(ictx.MetadataFromContext(cn.Context()), "host")
	if got != "example.local:80" {
		t.Errorf("host from Context() = %q, want %q", got, "example.local:80")
	}
}

// TestBindUDPConnContext is the same check for the UDP reverse-tunnel conn.
func TestBindUDPConnContext(t *testing.T) {
	md := mdata.Metadata(xmd.NewMetadata(map[string]any{"host": "example.local:80"}))
	cn := &bindUDPConn{
		Conn:       &net.TCPConn{},
		localAddr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		remoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80},
		md:         md,
	}

	got := mdutil.GetString(ictx.MetadataFromContext(cn.Context()), "host")
	if got != "example.local:80" {
		t.Errorf("host from Context() = %q, want %q", got, "example.local:80")
	}
}
