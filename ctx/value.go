package ctx

import (
	"context"
	"net"
)

type Context interface {
	Context() context.Context
}

type WithContext interface {
	WithContext(ctx context.Context)
}

type srcAddrKey struct{}

func ContextWithSrcAddr(ctx context.Context, addr net.Addr) context.Context {
	return context.WithValue(ctx, srcAddrKey{}, addr)
}

func SrcAddrFromContext(ctx context.Context) net.Addr {
	v, _ := ctx.Value(srcAddrKey{}).(net.Addr)
	return v
}

type dstAddrKey struct{}

func ContextWithDstAddr(ctx context.Context, addr net.Addr) context.Context {
	return context.WithValue(ctx, dstAddrKey{}, addr)
}

func DstAddrFromContext(ctx context.Context) net.Addr {
	v, _ := ctx.Value(dstAddrKey{}).(net.Addr)
	return v
}

type (
	Sid string
	// sidKey saves the session ID.
	sidKey struct{}
)

func (s Sid) String() string {
	return string(s)
}

func ContextWithSid(ctx context.Context, sid Sid) context.Context {
	return context.WithValue(ctx, sidKey{}, sid)
}

func SidFromContext(ctx context.Context) Sid {
	v, _ := ctx.Value(sidKey{}).(Sid)
	return v
}

type (
	// hashKey saves the hash source for Selector.
	hashKey struct{}
	Hash    struct {
		Source string
	}
)

func ContextWithHash(ctx context.Context, hash *Hash) context.Context {
	return context.WithValue(ctx, hashKey{}, hash)
}

func HashFromContext(ctx context.Context) *Hash {
	if v, _ := ctx.Value(hashKey{}).(*Hash); v != nil {
		return v
	}
	return nil
}

type (
	ClientID    string
	clientIDKey struct{}
)

func (s ClientID) String() string {
	return string(s)
}

func ContextWithClientID(ctx context.Context, clientID ClientID) context.Context {
	return context.WithValue(ctx, clientIDKey{}, clientID)
}

func ClientIDFromContext(ctx context.Context) ClientID {
	v, _ := ctx.Value(clientIDKey{}).(ClientID)
	return v
}
