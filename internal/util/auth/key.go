package auth

import (
	"context"
)

type idKey struct{}
type ID string

type addrKey struct{}
type ClientAddr string

var (
	clientIDKey   = &idKey{}
	clientAddrKey = &addrKey{}
)

func ContextWithID(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, clientIDKey, id)
}

func IDFromContext(ctx context.Context) ID {
	v, _ := ctx.Value(clientIDKey).(ID)
	return v
}

func ContextWithClientAddr(ctx context.Context, addr ClientAddr) context.Context {
	return context.WithValue(ctx, clientAddrKey, addr)
}

func ClientAddrFromContext(ctx context.Context) ClientAddr {
	v, _ := ctx.Value(clientAddrKey).(ClientAddr)
	return v
}
