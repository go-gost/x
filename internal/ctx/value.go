// Package ctx provides typed context value helpers for passing per-request
// data (buffer, logger, metadata, recorder objects) through the handler chain.
package ctx

import (
	"bytes"
	"context"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metadata"
	xrecorder "github.com/go-gost/x/recorder"
)

type bufferKey struct{}

// ContextWithBuffer returns a copy of ctx with the given buffer stored.
// The buffer is used by dialers and connectors to reuse a *bytes.Buffer
// for protocol handshake data (e.g. TLS ClientHello, HTTP requests).
func ContextWithBuffer(ctx context.Context, buffer *bytes.Buffer) context.Context {
	return context.WithValue(ctx, bufferKey{}, buffer)
}

// BufferFromContext returns the *bytes.Buffer stored in ctx, or nil.
func BufferFromContext(ctx context.Context) *bytes.Buffer {
	v, _ := ctx.Value(bufferKey{}).(*bytes.Buffer)
	return v
}

type loggerKey struct{}

// ContextWithLogger returns a copy of ctx with the given logger stored.
func ContextWithLogger(ctx context.Context, log logger.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, log)
}

// LoggerFromContext returns the logger stored in ctx, or nil.
func LoggerFromContext(ctx context.Context) logger.Logger {
	v, _ := ctx.Value(loggerKey{}).(logger.Logger)
	return v
}

type mdKey struct{}

// ContextWithMetadata returns a copy of ctx with the given metadata stored.
func ContextWithMetadata(ctx context.Context, md metadata.Metadata) context.Context {
	return context.WithValue(ctx, mdKey{}, md)
}

// MetadataFromContext returns the metadata stored in ctx, or nil.
func MetadataFromContext(ctx context.Context) metadata.Metadata {
	v, _ := ctx.Value(mdKey{}).(metadata.Metadata)
	return v
}

type recorderObjectCtxKey struct{}

// ContextWithRecorderObject returns a copy of ctx with the given recorder object stored.
func ContextWithRecorderObject(ctx context.Context, ro *xrecorder.HandlerRecorderObject) context.Context {
	return context.WithValue(ctx, recorderObjectCtxKey{}, ro)
}

// RecorderObjectFromContext returns the recorder object stored in ctx, or nil.
func RecorderObjectFromContext(ctx context.Context) *xrecorder.HandlerRecorderObject {
	v, _ := ctx.Value(recorderObjectCtxKey{}).(*xrecorder.HandlerRecorderObject)
	return v
}
