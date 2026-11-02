// Package httptunnel provides the pieces shared by the HTTP tunnel dialers and
// connectors: a replayable tunnel body and the redirect policy a tunnel client
// must use.
package httptunnel

import (
	"io"
	"net/http"
	"sync"
)

// Body carries the client-to-server half of a tunnel as the body of an HTTP
// request (CONNECT, or GET for a path-based endpoint).
//
// The body has no content until the request is sent, so every attempt needs a
// new pipe. When the transport retries the request on another connection (the
// server sent GOAWAY, or the connection broke, before the stream was opened),
// it resends the same *http.Request. Without Request.GetBody the retry reuses
// the pipe that the previous attempt already closed (golang/go#82177), and the
// tunnel is left with a dead write side.
//
// GetBody hands out a fresh pipe per attempt and Writer returns the writer of
// the pipe handed out last. That is the pipe the transport sends, because
// GetBody runs synchronously on the goroutine that calls Client.Do, before the
// next attempt starts. Nothing is written before the dial returns, so a fresh
// pipe is an exact replacement for the closed one.
type Body struct {
	mu sync.Mutex
	pr *io.PipeReader
	pw *io.PipeWriter
}

// NewBody returns a Body whose first pipe is ready to be sent.
func NewBody() *Body {
	b := &Body{}
	b.pr, b.pw = io.Pipe()
	return b
}

// Reader returns the body for the first attempt.
func (b *Body) Reader() io.ReadCloser {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pr
}

// GetBody implements http.Request.GetBody.
func (b *Body) GetBody() (io.ReadCloser, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pr, b.pw = io.Pipe()
	return b.pr, nil
}

// Writer returns the write side of the tunnel: the writer of the pipe handed
// out last, which is the pipe the transport reads.
func (b *Body) Writer() io.WriteCloser {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pw
}

// CloseWithError closes both ends of the current pipe with err: the transport
// is left with a failed body read, and writes to the tunnel fail with err.
func (b *Body) CloseWithError(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pr.CloseWithError(err)
	b.pw.CloseWithError(err)
}

// NoRedirect makes a tunnel client return a redirect response instead of
// following it. A tunnel request carries its data in the body, and net/http
// drops the body when it follows 301/302/303 and does not follow 307/308
// without Request.GetBody. Either way the redirected request has no body, so
// following it would hand back a connection whose write side is never read.
// The response is returned to the caller as a failed attempt instead, which
// the handler can retry.
func NoRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
