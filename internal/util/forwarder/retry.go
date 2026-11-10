package forwarder

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-gost/core/chain"
	mdutil "github.com/go-gost/x/metadata/util"
)

// Node metadata keys that opt a node into per-route HTTP retries. An absent
// retry.max or a non-positive value disables retries for the node.
const (
	retryMaxMetadataKey   = "retry.max"
	retryCodesMetadataKey = "retry.codes"
	defaultRetryCodes     = "429,5xx"
)

// retryBodyLimit caps the request body that may be buffered for replay.
// It is a variable so tests can lower it.
var retryBodyLimit = 32 << 20

// retryState carries the retry budget and the serialized request replayed by
// later attempts. A nil state means the request is not retryable.
type retryState struct {
	budget  int
	retries int
	codes   chain.FailCodes
	replay  []byte
	start   time.Time
}

// newRetryState builds the retry state for the selected node. It returns nil
// when the node is nil, retries are disabled for the node, or the request
// cannot be buffered for replay.
func newRetryState(req *http.Request, node *chain.Node) *retryState {
	if node == nil || req == nil {
		return nil
	}

	md := node.Options().Metadata
	budget := mdutil.GetInt(md, retryMaxMetadataKey)
	if budget <= 0 {
		return nil
	}

	codes := defaultRetryCodes
	if v := mdutil.GetString(md, retryCodesMetadataKey); v != "" {
		codes = v
	}

	replay, ok := bufferRetryRequest(req)
	if !ok {
		return nil
	}

	return &retryState{
		budget: budget,
		codes:  parseRetryCodes(codes),
		replay: replay,
		start:  time.Now(),
	}
}

// parseRetryCodes parses a comma-separated list of HTTP status codes to retry:
// exact codes (e.g. 429) and hundred-level wildcards (e.g. 5xx becomes 5, which
// chain.FailCodes matches against 500-599). Invalid tokens are skipped; an
// empty or all-invalid list yields nil.
func parseRetryCodes(s string) chain.FailCodes {
	var codes chain.FailCodes
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if n, err := strconv.Atoi(tok); err == nil {
			if n >= 100 {
				codes = append(codes, n)
			}
			continue
		}
		if n, ok := parseRetryCodeWildcard(tok); ok {
			codes = append(codes, n)
		}
	}
	return codes
}

// parseRetryCodeWildcard parses a hundred-level wildcard such as "5xx" into
// its hundred-level prefix (5).
func parseRetryCodeWildcard(tok string) (int, bool) {
	if len(tok) != 3 {
		return 0, false
	}
	if tok[0] < '0' || tok[0] > '9' {
		return 0, false
	}
	if (tok[1] != 'x' && tok[1] != 'X') || (tok[2] != 'x' && tok[2] != 'X') {
		return 0, false
	}
	return int(tok[0] - '0'), true
}

// bufferRetryRequest serializes the request so a later attempt can replay it,
// and leaves req with a fresh body reader (http.NoBody for an empty body) for
// the first attempt. It returns (nil, false) with req unchanged when the
// request cannot be replayed safely: it carries Expect: 100-continue, its body
// is over retryBodyLimit, or it cannot be read or written.
//
// Call this on the pristine client request, before httpRoundTrip applies the
// selected node's host/URL/header/body rewrites or wraps the body for
// recording. The snapshot is replayed against a different node, so every
// retry re-applies that node's rewrites on top of these bytes; replaying the
// already-rewritten request would send the failed node's target to the new
// one. The body is replaced with a fresh reader for attempt 1.
func bufferRetryRequest(req *http.Request) ([]byte, bool) {
	if req == nil {
		return nil, false
	}

	// The client waits for a 100 Continue response before sending the body, so
	// reading it here would stall the exchange.
	if strings.Contains(strings.ToLower(req.Header.Get("Expect")), "100-continue") {
		return nil, false
	}
	if req.ContentLength > int64(retryBodyLimit) {
		return nil, false
	}

	var body []byte
	hasBody := req.Body != nil
	if hasBody {
		// Read one byte past the limit so an oversized body is detected
		// without ever buffering more than the limit.
		read, err := io.ReadAll(io.LimitReader(req.Body, int64(retryBodyLimit)+1))
		if err != nil || len(read) > retryBodyLimit {
			req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(read), req.Body))
			return nil, false
		}
		body = read
	}

	// Normalize the head so the serialized request carries an explicit length
	// instead of a transfer encoding the client may have used.
	req.ContentLength = int64(len(body))
	req.TransferEncoding = nil
	req.Header.Del("Transfer-Encoding")
	if hasBody {
		req.Body = bufferedRetryBody(body)
	}

	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		if hasBody {
			req.Body = bufferedRetryBody(body)
		}
		return nil, false
	}

	if hasBody {
		// req.Write consumes (and closes) the body reader; hand attempt 1 a
		// fresh one.
		req.Body = bufferedRetryBody(body)
	}

	return buf.Bytes(), true
}

// bufferedRetryBody returns a body over the buffered bytes. An empty body
// becomes http.NoBody: a non-nil empty reader would make the request's
// outgoing length -1, so the serialized head would carry
// Transfer-Encoding: chunked instead of the original no-body framing.
func bufferedRetryBody(body []byte) io.ReadCloser {
	if len(body) == 0 {
		return http.NoBody
	}
	return io.NopCloser(bytes.NewReader(body))
}

// replayRetryRequest rebuilds a request from bytes produced by
// bufferRetryRequest. The returned request has a fresh body reader and can be
// written again.
func replayRetryRequest(b []byte) (*http.Request, error) {
	return http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
}
