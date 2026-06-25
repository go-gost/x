package net

import (
	"context"
	"fmt"
	"net"

	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/resolver"
	ctxvalue "github.com/go-gost/x/ctx"
)

// Resolve resolves addr to a concrete IP address. If hosts is non-nil, it is
// consulted first. If r is non-nil and no host mapping matched, the resolver
// is used. If neither is available, the address is returned unchanged so that
// the original hostname is preserved for downstream connectors (e.g., SOCKS5
// ATYP=domain). DNS resolution is deferred to the final TCP dialer, which uses
// a pure-Go resolver to avoid cgo thread exhaustion.
func Resolve(ctx context.Context, network, addr string, r resolver.Resolver, hosts hosts.HostMapper, log logger.Logger) (string, error) {
	if addr == "" {
		return addr, nil
	}

	host, port, _ := net.SplitHostPort(addr)
	if host == "" {
		return addr, nil
	}

	if log == nil {
		log = logger.Default()
	}
	log = log.WithFields(map[string]any{
		"sid": ctxvalue.SidFromContext(ctx),
	})

	if hosts != nil {
		if ips, _ := hosts.Lookup(ctx, network, host); len(ips) > 0 {
			log.Debugf("hit host mapper: %s -> %s", host, ips)
			return net.JoinHostPort(ips[0].String(), port), nil
		}
	}

	if r != nil {
		ips, err := r.Resolve(ctx, network, host)
		if err != nil {
			if err == resolver.ErrInvalid {
				return addr, nil
			}
			log.Error(err)
		}
		if len(ips) == 0 {
			return "", fmt.Errorf("resolver: domain %s does not exist", host)
		}
		return net.JoinHostPort(ips[0].String(), port), nil
	}

	// Return the address unchanged so that the original hostname is
	// preserved through the proxy chain. DNS resolution happens in the
	// final TCP dialer (dialer.go) which uses net.Resolver{PreferGo: true}
	// to avoid cgo-based lookups that block OS threads.
	return addr, nil
}
