package masque

import (
	"net/http"
	"testing"
)

func TestNewTCPConnectRequestUsesStandardConnect(t *testing.T) {
	req := newTCPConnectRequest("example.com:443")

	if req.Method != http.MethodConnect {
		t.Fatalf("expected CONNECT method, got %s", req.Method)
	}
	if req.Host != "example.com:443" {
		t.Fatalf("expected target authority, got %s", req.Host)
	}
	if req.Proto != "" {
		t.Fatalf("standard CONNECT must not set :protocol, got %q", req.Proto)
	}
	if req.ProtoMajor != 3 {
		t.Fatalf("expected HTTP/3 request, got HTTP/%d", req.ProtoMajor)
	}
}
