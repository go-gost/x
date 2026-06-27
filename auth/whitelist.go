package auth

import (
	"context"
	"net"
	"strings"

	"github.com/go-gost/core/auth"
	xctx "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/matcher"
)

// whitelistedAuthenticator wraps an Authenticator to skip authentication
// for client IPs matching the configured whitelist patterns.
type whitelistedAuthenticator struct {
	auther      auth.Authenticator
	ipMatcher   matcher.Matcher
	cidrMatcher matcher.Matcher
}

// WhitelistedAuthenticator returns an Authenticator that skips the underlying
// auther when the client's IP address matches one of the given patterns.
// Patterns may be IP addresses (e.g. "192.168.1.1") or CIDR ranges
// (e.g. "10.0.0.0/8"). Invalid patterns are silently ignored.
func WhitelistedAuthenticator(auther auth.Authenticator, patterns []string) auth.Authenticator {
	var ips []net.IP
	var inets []*net.IPNet
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if ip := net.ParseIP(pattern); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if _, inet, err := net.ParseCIDR(pattern); err == nil {
			inets = append(inets, inet)
		}
	}
	return &whitelistedAuthenticator{
		auther:      auther,
		ipMatcher:   matcher.IPMatcher(ips),
		cidrMatcher: matcher.CIDRMatcher(inets),
	}
}

func (w *whitelistedAuthenticator) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	if srcAddr := xctx.SrcAddrFromContext(ctx); srcAddr != nil {
		host, _, err := net.SplitHostPort(srcAddr.String())
		if err == nil && host != "" {
			if w.ipMatcher.Match(host) || w.cidrMatcher.Match(host) {
				return "", true
			}
		}
	}
	if w.auther != nil {
		return w.auther.Authenticate(ctx, user, password, opts...)
	}
	return "", false
}
