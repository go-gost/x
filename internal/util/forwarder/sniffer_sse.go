package forwarder

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/rewriter"
	xctx "github.com/go-gost/x/ctx"
	"github.com/klauspost/compress/zstd"
)

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
	for i := 0; i < len(data)-1; i++ {
		if data[i] == '\r' && data[i+1] == '\r' {
			return i + 2, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, bufio.ErrFinalToken
	}
	return 0, nil, nil
}

// rewriteBody wraps an io.ReadCloser and applies the rewrite chain.
//
// Three processing modes:
//
// 1. Non-streaming (plain): eagerly buffer the entire body, rewrite once,
//    expose the final ContentLength.
//
// 2. Non-streaming (compressed): decompress, rewrite, recompress, expose
//    the final ContentLength.
//
// 3. SSE streaming: split on \n\n via bufio.Scanner, rewrite each event
//    independently. The first event carries sse_phase:"start", subsequent
//    events carry sse_phase:"event", and when the scanner hits EOF an
//    empty-body apply(nil, sse_phase:"end") is emitted so Rewriter plugins
//    can append a trailing event (e.g. message_stop for LLM API conversion).
type rewriteBody struct {
	ctx         context.Context
	src         io.ReadCloser
	rewrites    []chain.HTTPBodyRewriteSettings
	contentType string
	streaming   bool

	scanner       *bufio.Scanner
	buf           bytes.Buffer
	contentLength int64 // >= 0 for non-streaming bodies; -1 for streaming

	// SSE stream lifecycle state.
	eventIndex int  // incremented per SSE event for the "event" phase
	ended      bool // true after the stream-end phase has been emitted
	scannerErr error // non-nil when scanner terminated with an error

	sid string // session ID, cached from context at construction time

	// Protocol detection metadata for Rewriter plugins.
	direction string // "request" or "response"
	uri       string // HTTP request path (e.g. "/v1/messages")
}

// multiReadCloser combines an io.Reader with an io.Closer, used when
// replaying buffered prefix data followed by the original source.
type multiReadCloser struct {
	r io.Reader
	c io.Closer
}

func (m *multiReadCloser) Read(p []byte) (int, error) { return m.r.Read(p) }
func (m *multiReadCloser) Close() error               { return m.c.Close() }

// defaultMaxChunkSize is the default MaxChunkSize for chunked non-streaming
// bodies when no rewrite rule explicitly sets one. 1MB covers typical LLM
// responses without risking OOM on unbounded bodies.
const defaultMaxChunkSize = 1 << 20 // 1MB

// newRewriteBody returns an io.ReadCloser that rewrites data read from src
// through the given rewrite chain. Returns nil, nil when no rewrites are
// configured, or for chunked/unknown-length non-streaming bodies.
// For compressed bodies (Content-Encoding set), the body is decompressed,
// rewritten, and recompressed transparently. Returns nil, err when the
// upstream body cannot be read or the rewrite chain fails.
func newRewriteBody(ctx context.Context, src io.ReadCloser, rewrites []chain.HTTPBodyRewriteSettings, contentType, contentEncoding string, contentLength int64, direction, uri string) (*rewriteBody, error) {
	if len(rewrites) == 0 {
		return nil, nil
	}

	ct, _, _ := strings.Cut(contentType, ";")
	ct = strings.TrimSpace(ct)
	streaming := strings.HasPrefix(ct, "text/event-stream")

	// Bounded buffering for chunked/unknown-length non-streaming bodies.
	if !streaming && contentLength < 0 {
		var maxChunkSize int
		for _, rw := range rewrites {
			if rw.MaxChunkSize > maxChunkSize {
				maxChunkSize = rw.MaxChunkSize
			}
		}
		if maxChunkSize == 0 {
			maxChunkSize = defaultMaxChunkSize
		}
		limited := io.LimitReader(src, int64(maxChunkSize+1))
		buf, err := io.ReadAll(limited)
		if err != nil {
			return nil, err
		}
		if len(buf) > maxChunkSize {
			// Overflow: passthrough without rewriting.
			// ContentLength stays -1 so Go re-chunk-encodes on Write.
			rb := &rewriteBody{
				ctx:           ctx,
				src:           &multiReadCloser{r: io.MultiReader(bytes.NewReader(buf), src), c: src},
				contentType:   ct,
				streaming:     false,
				contentLength: -1,
			}
			rb.sid = xctx.SidFromContext(ctx).String()
			rb.direction = direction
			rb.uri = uri
			return rb, nil
		}
		// Fits: rewrite and set ContentLength.
		rb := &rewriteBody{
			ctx:         ctx,
			rewrites:    rewrites,
			contentType: ct,
			streaming:   false,
			contentLength: -1,
		}
		rb.sid = xctx.SidFromContext(ctx).String()
		rb.direction = direction
		rb.uri = uri
		if contentEncoding != "" {
			// Compressed: decompress → rewrite → recompress.
			var hasTypeMatch bool
			for _, rw := range rewrites {
				rt := rw.Type
				if rt == "" {
					if rw.Rewriter != nil {
						rt = "*"
					} else {
						rt = "text/html"
					}
				}
				if rt == "*" || strings.Contains(rt, ct) {
					hasTypeMatch = true
					break
				}
			}
			if !hasTypeMatch {
				rb.src = io.NopCloser(bytes.NewReader(buf))
				rb.contentLength = int64(len(buf))
				return rb, nil
			}
			decoded, err := decompressBody(buf, contentEncoding)
			if err != nil {
				return nil, err
			}
			rewritten, err := rb.apply(decoded, rb.baseMetadataOpt())
			if err != nil {
				return nil, err
			}
			recompressed, err := compressBody(rewritten, contentEncoding)
			if err != nil {
				return nil, err
			}
			rb.src = io.NopCloser(bytes.NewReader(recompressed))
			rb.contentLength = int64(len(recompressed))
		} else {
			rewritten, err := rb.apply(buf, rb.baseMetadataOpt())
			if err != nil {
				return nil, err
			}
			rb.src = io.NopCloser(bytes.NewReader(rewritten))
			rb.contentLength = int64(len(rewritten))
		}
		return rb, nil
	}

	rb := &rewriteBody{
		ctx:           ctx,
		src:           src,
		rewrites:      rewrites,
		contentType:   ct,
		streaming:     streaming,
		contentLength: -1,
	}
	rb.sid = xctx.SidFromContext(ctx).String()
	rb.direction = direction
	rb.uri = uri
	mdOpts := []rewriter.RewriteOption{rb.baseMetadataOpt()}

	if contentEncoding != "" {
		if streaming {
			return nil, nil
		}
		// Early exit if no rewrite rule matches this content type
		// (avoids unnecessary decompress-recompress cycle).
		var hasTypeMatch bool
		for _, rw := range rewrites {
			rt := rw.Type
			if rt == "" {
				if rw.Rewriter != nil {
					rt = "*"
				} else {
					rt = "text/html"
				}
			}
			if rt == "*" || strings.Contains(rt, ct) {
				hasTypeMatch = true
				break
			}
		}
		if !hasTypeMatch {
			return nil, nil
		}
		// Compressed non-streaming: decompress, rewrite, recompress.
		body, err := drainBody(src)
		if err != nil {
			return nil, err
		}
		if len(body) == 0 {
			return nil, nil
		}
		decoded, err := decompressBody(body, contentEncoding)
		if err != nil {
			return nil, err
		}
		rewritten, err := rb.apply(decoded, mdOpts...)
		if err != nil {
			return nil, err
		}
		recompressed, err := compressBody(rewritten, contentEncoding)
		if err != nil {
			return nil, err
		}
		rb.src = io.NopCloser(bytes.NewReader(recompressed))
		rb.contentLength = int64(len(recompressed))
		return rb, nil
	}

	if !streaming {
		// Non-streaming: eagerly read and rewrite so the caller knows the
		// final content length.
		body, err := drainBody(src)
		if err != nil {
			return nil, err
		}
		rewritten, err := rb.apply(body, mdOpts...)
		if err != nil {
			return nil, err
		}
		rb.src = io.NopCloser(bytes.NewReader(rewritten))
		rb.contentLength = int64(len(rewritten))
	} else {
		// SSE streaming: scan events split on \n\n and rewrite each one
	// independently on Read. Lifecycle phases (first event = start,
	// subsequent = event, EOF = end) are assigned in Read().
		scanner := bufio.NewScanner(src)
		scanner.Split(scanSSEEvents)
		scanner.Buffer(make([]byte, 64*1024), 64*1024*1024)
		rb.scanner = scanner
	}

	return rb, nil
}

func (b *rewriteBody) Read(p []byte) (n int, err error) {
	for {
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
				if b.ended {
					if b.scannerErr != nil {
						return 0, b.scannerErr
					}
					return 0, io.EOF
				}
				// End of upstream SSE events — emit stream end phase.
				// This empty-body call lets Rewriter plugins append a
				// trailing event (e.g. message_stop for LLM conversion).
				b.ended = true
				md := map[string]any{
					"sid":         b.sid,
			"direction": b.direction,
			"uri":       b.uri,
					"sse_phase":   "end",
					"event_index": b.eventIndex,
				}
				rewritten, endErr := b.apply(nil, rewriter.MetadataRewriteOption(md))
				if endErr != nil {
					return 0, endErr
				}
				if len(rewritten) > 0 {
					b.buf.Write(rewritten)
					writeSSEStreamDelim(&b.buf, rewritten)
				}
				return b.buf.Read(p)
			}
			// Scanner error (e.g. upstream connection reset): emit the end
			// phase so Rewriter plugins can send a terminal event
			// (response.failed / message_stop), then return the error
			// after the buffer drains.
			if !b.ended {
				b.ended = true
				b.scannerErr = err
				md := map[string]any{
					"sid":          b.sid,
			"direction": b.direction,
			"uri":       b.uri,
					"sse_phase":    "end",
					"event_index":  b.eventIndex,
					"stream_error": err.Error(),
				}
				rewritten, _ := b.apply(nil, rewriter.MetadataRewriteOption(md))
				if len(rewritten) > 0 {
					b.buf.Write(rewritten)
					writeSSEStreamDelim(&b.buf, rewritten)
					return b.buf.Read(p)
				}
			}
			return 0, err
		}

		// Copy token (scanner.Bytes() is only valid until next Scan()).
		event := make([]byte, len(b.scanner.Bytes()))
		copy(event, b.scanner.Bytes())

		// SSE lifecycle phases — assigned to real events so the Rewriter
		// can distinguish first (start), middle (event), and last event
		// without synthetic signals. On EOF, apply(nil, end) produces any
		// trailing event (e.g. message_stop for LLM API conversion).
		phase := "event"
		if b.eventIndex == 0 {
			phase = "start"
		}
		md := map[string]any{
			"sid":          b.sid,
			"direction": b.direction,
			"uri":       b.uri,
			"sse_phase":    phase,
			"event_index":  b.eventIndex,
		}
		b.eventIndex++

		rewritten, err := b.apply(event, rewriter.MetadataRewriteOption(md))
		if err != nil {
			return 0, err
		}
		if len(rewritten) > 0 {
			b.buf.Write(rewritten)
			writeSSEStreamDelim(&b.buf, rewritten)
		}
		// Loop to flush the buffer or scan the next event.
	}
}

func (b *rewriteBody) Close() error {
	return b.src.Close()
}

// baseMetadata returns rewriter metadata with all available fields.
func (b *rewriteBody) baseMetadata() map[string]any {
	md := map[string]any{}
	if b.sid != "" {
		md["sid"] = b.sid
	}
	if b.direction != "" {
		md["direction"] = b.direction
	}
	if b.uri != "" {
		md["uri"] = b.uri
	}
	return md
}

// baseMetadataOpt returns a RewriteOption wrapping baseMetadata.
func (b *rewriteBody) baseMetadataOpt() rewriter.RewriteOption {
	return rewriter.MetadataRewriteOption(b.baseMetadata())
}

// ponytail: guard against plugin already having added \n\n delimiter
func writeSSEStreamDelim(buf *bytes.Buffer, data []byte) {
	if len(data) < 2 || data[len(data)-1] != '\n' || data[len(data)-2] != '\n' {
		buf.Write([]byte("\n\n"))
	}
}

func decompressBody(data []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	case "deflate":
		r, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	case "br":
		return io.ReadAll(brotli.NewReader(bytes.NewReader(data)))
	case "zstd":
		r, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	default:
		// identity or unknown — pass through.
		return data, nil
	}
}

func compressBody(data []byte, encoding string) ([]byte, error) {
	var buf bytes.Buffer
	switch encoding {
	case "gzip":
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
	case "deflate":
		w := zlib.NewWriter(&buf)
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
	case "br":
		w := brotli.NewWriter(&buf)
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
	case "zstd":
		w, err := zstd.NewWriter(&buf)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
	default:
		return data, nil
	}
	return buf.Bytes(), nil
}

// apply runs the rewrite chain on body bytes.
// Returns the (possibly unchanged) body and any error from a plugin Rewriter.
func (b *rewriteBody) apply(body []byte, opts ...rewriter.RewriteOption) ([]byte, error) {
	if len(body) == 0 && len(opts) == 0 {
		return body, nil
	}
	for _, rw := range b.rewrites {
		rewriteType := rw.Type
		if rewriteType == "" {
			if rw.Rewriter != nil {
				rewriteType = "*"
			} else {
				rewriteType = "text/html"
			}
		}
		if rewriteType != "*" && !strings.Contains(rewriteType, b.contentType) {
			continue
		}

		if rw.Rewriter != nil {
			if body == nil || rw.Pattern == nil || rw.Pattern.Match(body) {
				rewritten, err := rw.Rewriter.Rewrite(b.ctx, body, opts...)
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
