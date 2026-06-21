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
// is used. If neither is available, Go's native pure-Go resolver is used as a
// fallback to avoid cgo-based DNS lookups that would block OS threads.
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

	// A literal IP address needs no resolution.
	if net.ParseIP(host) != nil {
		return addr, nil
	}

	// Fallback to Go's native (pure-Go) resolver when no custom resolver or
	// host mapper is configured. This avoids cgo-based DNS lookups in
	// downstream net.Dialer.DialContext which would block OS threads and
	// cause thread exhaustion under high connection concurrency.
	lr := &net.Resolver{PreferGo: true}
	ips, err := lr.LookupIP(ctx, "ip", host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolver: domain %s does not exist", host)
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}
