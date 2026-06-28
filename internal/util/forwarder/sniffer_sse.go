package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/go-gost/core/chain"
)

// isStreamingResponse reports whether resp is a text/event-stream response.
func isStreamingResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "text/event-stream")
}

// scanSSEEvents is a bufio.SplitFunc that splits SSE events on \n\n (or \r\n\r\n).
// The delimiter is consumed but not included in the token.
func scanSSEEvents(data []byte, atEOF bool) (advance int, token []byte, err error) {
	for i := 0; i < len(data)-1; i++ {
		if data[i] == '\n' && data[i+1] == '\n' {
			return i + 2, data[:i], nil
		}
	}
	for i := 0; i < len(data)-3; i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			return i + 4, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, bufio.ErrFinalToken
	}
	return 0, nil, nil
}

// rewriteBody wraps an io.ReadCloser and applies the rewrite chain.
// For text/event-stream responses, each SSE event is rewritten independently
// (streaming). For all other responses, the entire body is buffered and
// rewritten at once, exposing the final ContentLength.
type rewriteBody struct {
	ctx         context.Context
	src         io.ReadCloser
	rewrites    []chain.HTTPBodyRewriteSettings
	contentType string
	streaming   bool

	scanner       *bufio.Scanner
	buf           bytes.Buffer
	contentLength int64 // >= 0 for non-streaming bodies; -1 for streaming
}

// newRewriteBody returns an io.ReadCloser that rewrites data read from src
// through the given rewrite chain. Returns nil, nil when no rewrites are
// configured, the body is compressed (Content-Encoding set), or for
// chunked/unknown-length non-streaming bodies. Returns nil, err when the
// upstream body cannot be read or the rewrite chain fails.
func newRewriteBody(ctx context.Context, src io.ReadCloser, rewrites []chain.HTTPBodyRewriteSettings, contentType, contentEncoding string, contentLength int64) (*rewriteBody, error) {
	if len(rewrites) == 0 {
		return nil, nil
	}
	if contentEncoding != "" {
		return nil, nil
	}

	ct, _, _ := strings.Cut(contentType, ";")
	ct = strings.TrimSpace(ct)
	streaming := strings.HasPrefix(ct, "text/event-stream")

	// Don't eagerly buffer chunked/unknown-length non-streaming bodies.
	if !streaming && contentLength < 0 {
		return nil, nil
	}

	rb := &rewriteBody{
		ctx:           ctx,
		src:           src,
		rewrites:      rewrites,
		contentType:   ct,
		streaming:     streaming,
		contentLength: -1,
	}

	if !streaming {
		// Non-streaming: eagerly read and rewrite so the caller knows the
		// final content length.
		body, err := drainBody(src)
		if err != nil {
			return nil, err
		}
		rewritten, err := rb.apply(body)
		if err != nil {
			return nil, err
		}
		rb.src = io.NopCloser(bytes.NewReader(rewritten))
		rb.contentLength = int64(len(rewritten))
	} else {
		// Streaming (SSE): split on \n\n and rewrite each event.
		scanner := bufio.NewScanner(src)
		scanner.Split(scanSSEEvents)
		scanner.Buffer(make([]byte, 64*1024), 64*1024*1024)
		rb.scanner = scanner
	}

	return rb, nil
}

func (b *rewriteBody) Read(p []byte) (n int, err error) {
	if !b.streaming {
		return b.src.Read(p)
	}

	// SSE streaming: flush buffered rewritten event first.
	if b.buf.Len() > 0 {
		return b.buf.Read(p)
	}

	// Scan the next SSE event.
	if !b.scanner.Scan() {
		err = b.scanner.Err()
		if err == nil {
			err = io.EOF
		}
		return 0, err
	}

	// Copy token (scanner.Bytes() is only valid until next Scan()).
	event := make([]byte, len(b.scanner.Bytes()))
	copy(event, b.scanner.Bytes())

	rewritten, err := b.apply(event)
	if err != nil {
		return 0, err
	}
	b.buf.Write(rewritten)
	b.buf.Write([]byte("\n\n"))

	return b.buf.Read(p)
}

func (b *rewriteBody) Close() error {
	return b.src.Close()
}

// apply runs the rewrite chain on body bytes.
// Returns the (possibly unchanged) body and any error from a plugin Rewriter.
func (b *rewriteBody) apply(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}
	for _, rw := range b.rewrites {
		rewriteType := rw.Type
		if rewriteType == "" {
			rewriteType = "text/html"
		}
		if rewriteType != "*" && !strings.Contains(rewriteType, b.contentType) {
			continue
		}

		if rw.Rewriter != nil {
			if rw.Pattern == nil || rw.Pattern.Match(body) {
				rewritten, err := rw.Rewriter.Rewrite(b.ctx, body)
				if err != nil {
					return body, err
				}
				body = rewritten
			}
		} else if rw.Pattern != nil {
			body = rw.Pattern.ReplaceAll(body, rw.Replacement)
		}
	}
	return body, nil
}
