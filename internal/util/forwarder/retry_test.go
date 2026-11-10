package forwarder

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/x/metadata"
)

func TestParseRetryCodes(t *testing.T) {
	cases := []struct {
		in   string
		want chain.FailCodes
	}{
		{"429,5xx", chain.FailCodes{429, 5}},
		{" 502 , 503 ", chain.FailCodes{502, 503}},
		{"", nil},
		{"nope,99,5x", nil},
	}
	for _, c := range cases {
		if got := parseRetryCodes(c.in); !slices.Equal(got, c.want) {
			t.Errorf("parseRetryCodes(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNewRetryStateReadsNodeMetadata(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://up.example/v1/messages", strings.NewReader(`{"m":1}`))
	node := chain.NewNode("n", "127.0.0.1:1", chain.MetadataNodeOption(metadata.NewMetadata(map[string]any{
		"retry.max": 2, "retry.codes": "429,502",
	})))
	rs := newRetryState(req, node)
	if rs == nil {
		t.Fatal("nil retry state")
	}
	if rs.budget != 2 || !slices.Equal(rs.codes, chain.FailCodes{429, 502}) {
		t.Fatalf("state = %+v", rs)
	}
	got, err := replayRetryRequest(rs.replay)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(got.Body)
	if string(body) != `{"m":1}` {
		t.Fatalf("replayed body = %q", body)
	}
}

func TestNewRetryStateDefaultsAndSkips(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://up.example/", strings.NewReader("x"))

	noMeta := chain.NewNode("n", "127.0.0.1:1")
	if newRetryState(req, noMeta) != nil {
		t.Fatal("retried without metadata")
	}
	zero := chain.NewNode("n", "127.0.0.1:1", chain.MetadataNodeOption(metadata.NewMetadata(map[string]any{"retry.max": 0})))
	if newRetryState(req, zero) != nil {
		t.Fatal("retried with zero budget")
	}
	def := chain.NewNode("n", "127.0.0.1:1", chain.MetadataNodeOption(metadata.NewMetadata(map[string]any{"retry.max": 1})))
	if rs := newRetryState(req, def); rs == nil || !slices.Equal(rs.codes, chain.FailCodes{429, 5}) {
		t.Fatalf("default codes = %+v", rs)
	}
	req.Header.Set("Expect", "100-continue")
	if newRetryState(req, def) != nil {
		t.Fatal("buffered an Expect: 100-continue request")
	}
}

func TestBufferRetryRequestOverCapRestoresBody(t *testing.T) {
	old := retryBodyLimit
	retryBodyLimit = 4
	defer func() { retryBodyLimit = old }()

	req := httptest.NewRequest(http.MethodPost, "http://up.example/", strings.NewReader("12345"))
	req.ContentLength = -1 // force the read path instead of the length early-exit
	if _, ok := bufferRetryRequest(req); ok {
		t.Fatal("buffered a body over the limit")
	}
	body, err := io.ReadAll(req.Body)
	if err != nil || string(body) != "12345" {
		t.Fatalf("body after failed buffer = %q, %v", body, err)
	}
}

func TestBufferRetryRequestReplaysBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://up.example/", strings.NewReader("hello"))
	replay, ok := bufferRetryRequest(req)
	if !ok {
		t.Fatal("did not buffer")
	}
	again, err := replayRetryRequest(replay)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(again.Body)
	if string(body) != "hello" || again.ContentLength != 5 {
		t.Fatalf("replayed body = %q len %d", body, again.ContentLength)
	}
}

func TestBufferRetryRequestEmptyBodyKeepsNoBodyFraming(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://up.example/", strings.NewReader(""))
	if req.ContentLength != 0 {
		t.Fatalf("setup: ContentLength = %d", req.ContentLength)
	}

	replay, ok := bufferRetryRequest(req)
	if !ok {
		t.Fatal("did not buffer an empty body")
	}
	// Attempt 1 must keep the original no-body framing, not a chunked empty
	// body.
	if req.Body != http.NoBody || req.ContentLength != 0 {
		t.Fatalf("attempt 1 body = %v len %d", req.Body, req.ContentLength)
	}
	if bytes.Contains(replay, []byte("Transfer-Encoding")) {
		t.Fatalf("serialized a transfer encoding:\n%s", replay)
	}
	if !bytes.Contains(replay, []byte("Content-Length: 0\r\n")) {
		t.Fatalf("missing Content-Length: 0:\n%s", replay)
	}

	again, err := replayRetryRequest(replay)
	if err != nil {
		t.Fatal(err)
	}
	if again.Body != http.NoBody || again.ContentLength != 0 || len(again.TransferEncoding) != 0 {
		t.Fatalf("replayed body = %v len %d te %v",
			again.Body, again.ContentLength, again.TransferEncoding)
	}

	// The replay must re-serialize to the same head.
	var buf bytes.Buffer
	if err := again.Write(&buf); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != string(replay) {
		t.Fatalf("re-serialized replay =\n%s\nwant\n%s", got, replay)
	}
}

func TestBufferRetryRequestNonEmptyBodyUnaffected(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://up.example/", strings.NewReader("hello"))

	replay, ok := bufferRetryRequest(req)
	if !ok {
		t.Fatal("did not buffer")
	}
	if req.Body == http.NoBody || req.ContentLength != 5 {
		t.Fatalf("attempt 1 body = %v len %d", req.Body, req.ContentLength)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil || string(body) != "hello" {
		t.Fatalf("attempt 1 body = %q, %v", body, err)
	}
	if bytes.Contains(replay, []byte("Transfer-Encoding")) {
		t.Fatalf("serialized a transfer encoding:\n%s", replay)
	}
	if !bytes.Contains(replay, []byte("Content-Length: 5\r\n")) {
		t.Fatalf("missing Content-Length: 5:\n%s", replay)
	}

	again, err := replayRetryRequest(replay)
	if err != nil {
		t.Fatal(err)
	}
	if again.ContentLength != 5 || len(again.TransferEncoding) != 0 {
		t.Fatalf("replayed len %d te %v", again.ContentLength, again.TransferEncoding)
	}
	body, _ = io.ReadAll(again.Body)
	if string(body) != "hello" {
		t.Fatalf("replayed body = %q", body)
	}
}
