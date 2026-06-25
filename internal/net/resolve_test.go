package net

import (
	"context"
	"net"
	"testing"

	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/resolver"
)

type mockResolver struct {
	ips []net.IP
	err error
}

func (m *mockResolver) Resolve(ctx context.Context, network, host string, opts ...resolver.Option) ([]net.IP, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.ips, nil
}

type mockHostMapper struct {
	ips []net.IP
}

func (m *mockHostMapper) Lookup(ctx context.Context, network, host string, opts ...hosts.Option) ([]net.IP, bool) {
	if len(m.ips) == 0 {
		return nil, false
	}
	return m.ips, true
}

func TestResolve_EmptyAddr(t *testing.T) {
	ctx := context.Background()
	addr, err := Resolve(ctx, "tcp", "", nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if addr != "" {
		t.Errorf("expected empty, got %s", addr)
	}
}

func TestResolve_NoHost(t *testing.T) {
	ctx := context.Background()
	addr, err := Resolve(ctx, "tcp", ":8080", nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if addr != ":8080" {
		t.Errorf("expected :8080, got %s", addr)
	}
}

func TestResolve_HostMapperMatch(t *testing.T) {
	ctx := context.Background()
	mapper := &mockHostMapper{ips: []net.IP{net.ParseIP("10.0.0.1")}}
	r := &mockResolver{ips: []net.IP{net.ParseIP("192.168.1.1")}}

	addr, err := Resolve(ctx, "tcp", "example.com:8080", r, mapper, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if addr != "10.0.0.1:8080" {
		t.Errorf("expected 10.0.0.1:8080, got %s", addr)
	}
}

func TestResolve_Resolver(t *testing.T) {
	ctx := context.Background()
	r := &mockResolver{ips: []net.IP{net.ParseIP("192.168.1.1")}}

	addr, err := Resolve(ctx, "tcp", "example.com:8080", r, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if addr != "192.168.1.1:8080" {
		t.Errorf("expected 192.168.1.1:8080, got %s", addr)
	}
}

func TestResolve_ResolverInvalid(t *testing.T) {
	ctx := context.Background()
	r := &mockResolver{err: resolver.ErrInvalid}

	addr, err := Resolve(ctx, "tcp", "example.com:8080", r, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if addr != "example.com:8080" {
		t.Errorf("expected example.com:8080, got %s", addr)
	}
}

func TestResolve_ResolverOtherError(t *testing.T) {
	ctx := context.Background()
	r := &mockResolver{err: net.UnknownNetworkError("test-error")}

	_, err := Resolve(ctx, "tcp", "example.com:8080", r, nil, nil)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestResolve_ResolverEmptyResult(t *testing.T) {
	ctx := context.Background()
	r := &mockResolver{ips: nil}

	_, err := Resolve(ctx, "tcp", "example.com:8080", r, nil, nil)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestResolve_NoResolverNoHosts(t *testing.T) {
	// When no resolver and no host mapper are configured, the address is
	// returned unchanged so that the original hostname is preserved
	// through the proxy chain (e.g., SOCKS5 ATYP=domain).
	// DNS resolution is deferred to the final TCP dialer.
	ctx := context.Background()
	addr, err := Resolve(ctx, "tcp", "1.2.3.4:8080", nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if addr != "1.2.3.4:8080" {
		t.Errorf("expected 1.2.3.4:8080, got %s", addr)
	}
	addr, err = Resolve(ctx, "tcp", "example.com:8080", nil, nil, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if addr != "example.com:8080" {
		t.Errorf("expected example.com:8080, got %s", addr)
	}
}

func TestResolve_HostsNoMatchUsesResolver(t *testing.T) {
	ctx := context.Background()
	mapper := &mockHostMapper{}
	r := &mockResolver{ips: []net.IP{net.ParseIP("10.0.0.1")}}

	addr, err := Resolve(ctx, "tcp", "example.com:8080", r, mapper, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if addr != "10.0.0.1:8080" {
		t.Errorf("expected 10.0.0.1:8080, got %s", addr)
	}
}
