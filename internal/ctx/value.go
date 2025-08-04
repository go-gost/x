package ctx

import (
	"bytes"
	"context"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metadata"
	xctx "github.com/go-gost/x/ctx"
	xrecorder "github.com/go-gost/x/recorder"
)

type bufferKey struct{}

func ContextWithBuffer(ctx context.Context, buffer *bytes.Buffer) context.Context {
	return context.WithValue(ctx, bufferKey{}, buffer)
}

func BufferFromContext(ctx context.Context) *bytes.Buffer {
	v, _ := ctx.Value(bufferKey{}).(*bytes.Buffer)
	return v
}

type loggerKey struct{}

func ContextWithLogger(ctx context.Context, log logger.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, log)
}

func LoggerFromContext(ctx context.Context) logger.Logger {
	v, _ := ctx.Value(loggerKey{}).(logger.Logger)
	return v
}

type mdKey struct{}

func ContextWithMetadata(ctx context.Context, md metadata.Metadata) context.Context {
	return context.WithValue(ctx, mdKey{}, md)
}

func MetadataFromContext(ctx context.Context) metadata.Metadata {
	v, _ := ctx.Value(mdKey{}).(metadata.Metadata)
	return v
}

type recorderObjectCtxKey struct{}

func ContextWithRecorderObject(ctx context.Context, ro *xrecorder.HandlerRecorderObject) context.Context {
	return context.WithValue(ctx, recorderObjectCtxKey{}, ro)
}

func RecorderObjectFromContext(ctx context.Context) *xrecorder.HandlerRecorderObject {
	v, _ := ctx.Value(recorderObjectCtxKey{}).(*xrecorder.HandlerRecorderObject)
	return v
}

func Copy(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}

	ctx2 := context.Background()
	if v := xctx.SrcAddrFromContext(ctx); v != nil {
		ctx2 = xctx.ContextWithSrcAddr(ctx2, v)
	}
	if v := xctx.DstAddrFromContext(ctx); v != nil {
		ctx2 = xctx.ContextWithDstAddr(ctx2, v)
	}
	if v := xctx.SidFromContext(ctx); v != "" {
		ctx2 = xctx.ContextWithSid(ctx2, v)
	}
	if v := xctx.ClientIDFromContext(ctx); v != "" {
		ctx2 = xctx.ContextWithClientID(ctx2, v)
	}
	if v := MetadataFromContext(ctx); v != nil {
		ctx2 = ContextWithMetadata(ctx2, v)
	}

	return ctx2
}
