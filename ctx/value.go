// Package ctx provides typed context keys and helpers for passing per-request
// data (session ID, addresses, client ID, hash source) through the handler chain.
package ctx

import (
	"context"
	"net"
)

// Context is implemented by connections that carry a [context.Context].
type Context interface {
	Context() context.Context
}

type srcAddrKey struct{}

// ContextWithSrcAddr returns a copy of ctx that carries the source address addr.
func ContextWithSrcAddr(ctx context.Context, addr net.Addr) context.Context {
	return context.WithValue(ctx, srcAddrKey{}, addr)
}

// SrcAddrFromContext returns the source address stored in ctx, or nil if none is set.
func SrcAddrFromContext(ctx context.Context) net.Addr {
	v, _ := ctx.Value(srcAddrKey{}).(net.Addr)
	return v
}

type dstAddrKey struct{}

// ContextWithDstAddr returns a copy of ctx that carries the destination address addr.
func ContextWithDstAddr(ctx context.Context, addr net.Addr) context.Context {
	return context.WithValue(ctx, dstAddrKey{}, addr)
}

// DstAddrFromContext returns the destination address stored in ctx, or nil if none is set.
func DstAddrFromContext(ctx context.Context) net.Addr {
	v, _ := ctx.Value(dstAddrKey{}).(net.Addr)
	return v
}

type (
	// Sid is a session identifier carried in the context.
	Sid    string
	sidKey struct{}
)

// String implements fmt.Stringer.
func (s Sid) String() string {
	return string(s)
}

// ContextWithSid returns a copy of ctx that carries the session ID sid.
func ContextWithSid(ctx context.Context, sid Sid) context.Context {
	return context.WithValue(ctx, sidKey{}, sid)
}

// SidFromContext returns the session ID stored in ctx, or the zero value if none is set.
func SidFromContext(ctx context.Context) Sid {
	v, _ := ctx.Value(sidKey{}).(Sid)
	return v
}

type (
	hashKey struct{}
	// Hash carries the hash source used by selectors for sticky load balancing.
	Hash struct {
		Source string
	}
)

// ContextWithHash returns a copy of ctx that carries the hash source h.
func ContextWithHash(ctx context.Context, h *Hash) context.Context {
	return context.WithValue(ctx, hashKey{}, h)
}

// HashFromContext returns the hash source stored in ctx, or nil if none is set.
func HashFromContext(ctx context.Context) *Hash {
	v, _ := ctx.Value(hashKey{}).(*Hash)
	return v
}

type (
	// ClientID is a client identifier used for hash-based load balancing.
	ClientID    string
	clientIDKey struct{}
)

// String implements fmt.Stringer.
func (c ClientID) String() string {
	return string(c)
}

// ContextWithClientID returns a copy of ctx that carries the client ID clientID.
func ContextWithClientID(ctx context.Context, clientID ClientID) context.Context {
	return context.WithValue(ctx, clientIDKey{}, clientID)
}

// ClientIDFromContext returns the client ID stored in ctx, or the zero value if none is set.
func ClientIDFromContext(ctx context.Context) ClientID {
	v, _ := ctx.Value(clientIDKey{}).(ClientID)
	return v
}

type peerCertKey struct{}

// PeerCert carries the verified mTLS client certificate identity.
type PeerCert struct {
	CN          string
	SANs        []string
	Fingerprint string // SHA-256 hex of cert.Raw
}

// ContextWithPeerCert returns a copy of ctx that carries the peer cert.
func ContextWithPeerCert(ctx context.Context, cert *PeerCert) context.Context {
	return context.WithValue(ctx, peerCertKey{}, cert)
}

// PeerCertFromContext returns the peer cert stored in ctx, or nil.
func PeerCertFromContext(ctx context.Context) *PeerCert {
	v, _ := ctx.Value(peerCertKey{}).(*PeerCert)
	return v
}

// labelsKey saves the static service labels.
type labelsKey struct{}

// ContextWithLabels returns a new context carrying the given service labels.
func ContextWithLabels(ctx context.Context, labels map[string]string) context.Context {
	return context.WithValue(ctx, labelsKey{}, labels)
}

// LabelsFromContext returns the service labels stored in the context, or nil.
func LabelsFromContext(ctx context.Context) map[string]string {
	v, _ := ctx.Value(labelsKey{}).(map[string]string)
	return v
}
