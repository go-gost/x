package ctx

import "context"

// clientAddrKey saves the client address.
type clientAddrKey struct{}

type ClientAddr string

var (
	keyClientAddr clientAddrKey
)

func ContextWithClientAddr(ctx context.Context, addr ClientAddr) context.Context {
	return context.WithValue(ctx, keyClientAddr, addr)
}

func ClientAddrFromContext(ctx context.Context) ClientAddr {
	v, _ := ctx.Value(keyClientAddr).(ClientAddr)
	return v
}

// sidKey saves the session ID.
type sidKey struct{}
type Sid string

var (
	keySid sidKey
)

func ContextWithSid(ctx context.Context, sid Sid) context.Context {
	return context.WithValue(ctx, keySid, sid)
}

func SidFromContext(ctx context.Context) Sid {
	v, _ := ctx.Value(keySid).(Sid)
	return v
}

// hashKey saves the hash source for Selector.
type hashKey struct{}

type Hash struct {
	Source string
}

var (
	clientHashKey = &hashKey{}
)

func ContextWithHash(ctx context.Context, hash *Hash) context.Context {
	return context.WithValue(ctx, clientHashKey, hash)
}

func HashFromContext(ctx context.Context) *Hash {
	if v, _ := ctx.Value(clientHashKey).(*Hash); v != nil {
		return v
	}
	return nil
}

type clientIDKey struct{}
type ClientID string

var (
	keyClientID = &clientIDKey{}
)

func ContextWithClientID(ctx context.Context, clientID ClientID) context.Context {
	return context.WithValue(ctx, keyClientID, clientID)
}

func ClientIDFromContext(ctx context.Context) ClientID {
	v, _ := ctx.Value(keyClientID).(ClientID)
	return v
}
