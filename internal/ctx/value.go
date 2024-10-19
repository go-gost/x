package ctx

import (
	"context"

	xrecorder "github.com/go-gost/x/recorder"
)

type recorderObjectCtxKey struct{}

var (
	ctxKeyRecorderObject = &recorderObjectCtxKey{}
)

func ContextWithRecorderObject(ctx context.Context, ro *xrecorder.HandlerRecorderObject) context.Context {
	return context.WithValue(ctx, ctxKeyRecorderObject, ro)
}

func RecorderObjectFromContext(ctx context.Context) *xrecorder.HandlerRecorderObject {
	v, _ := ctx.Value(ctxKeyRecorderObject).(*xrecorder.HandlerRecorderObject)
	return v
}
