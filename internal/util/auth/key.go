package auth

import (
	"context"
)

type idKey struct{}

type ID string

var (
	clientIDKey = &idKey{}
)

func ContextWithID(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, clientIDKey, id)
}

func IDFromContext(ctx context.Context) ID {
	v, _ := ctx.Value(clientIDKey).(ID)
	return v
}
