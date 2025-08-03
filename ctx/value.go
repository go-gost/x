package ctx

import (
	"bytes"
	"context"
	"net"

	"github.com/go-gost/core/logger"
)

type ClientAddr string

func (a ClientAddr) String() string {
	return string(a)
}

// clientAddrKey saves the client address.
type clientAddrKey struct{}

var keyClientAddr clientAddrKey

func ContextWithClientAddr(ctx context.Context, addr ClientAddr) context.Context {
	return context.WithValue(ctx, keyClientAddr, addr)
}

func ClientAddrFromContext(ctx context.Context) ClientAddr {
	v, _ := ctx.Value(keyClientAddr).(ClientAddr)
	return v
}

type (
	srcAddrKey struct{}
	dstAddrKey struct{}
)

var (
	keySrcAddr srcAddrKey
	keyDstAddr dstAddrKey
)

func ContextWithSrcAddr(ctx context.Context, addr net.Addr) context.Context {
	return context.WithValue(ctx, keySrcAddr, addr)
}

func SrcAddrFromContext(ctx context.Context) net.Addr {
	v, _ := ctx.Value(keySrcAddr).(net.Addr)
	return v
}

func ContextWithDstAddr(ctx context.Context, addr net.Addr) context.Context {
	return context.WithValue(ctx, keyDstAddr, addr)
}

func DstAddrFromContext(ctx context.Context) net.Addr {
	v, _ := ctx.Value(keyDstAddr).(net.Addr)
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

type (
	// hashKey saves the hash source for Selector.
	hashKey struct{}
	Hash    struct {
		Source string
	}
)

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

type (
	ClientID    string
	clientIDKey struct{}
)

func (s ClientID) String() string {
	return string(s)
}

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

type bufferKey struct{}

var (
	keyBuffer = &bufferKey{}
)

func ContextWithBuffer(ctx context.Context, buffer *bytes.Buffer) context.Context {
	return context.WithValue(ctx, keyBuffer, buffer)
}

func BufferFromContext(ctx context.Context) *bytes.Buffer {
	v, _ := ctx.Value(keyBuffer).(*bytes.Buffer)
	return v
}

type loggerKey struct{}

var (
	keyLogger = &loggerKey{}
)

func ContextWithLogger(ctx context.Context, log logger.Logger) context.Context {
	return context.WithValue(ctx, keyLogger, log)
}

func LoggerFromContext(ctx context.Context) logger.Logger {
	v, _ := ctx.Value(keyLogger).(logger.Logger)
	return v
}
