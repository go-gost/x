package selector

import (
	"context"
)

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
