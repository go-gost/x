package forwarder

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	xlogger "github.com/go-gost/x/logger"
	"github.com/go-gost/x/metadata"
	xrecorder "github.com/go-gost/x/recorder"

	"github.com/go-gost/x/internal/util/sniffing"
)

// sequenceHop hands out nodes in order, repeating the last one once the list
// is exhausted. It stands in for the selector so a test can assert which node
// each attempt reached.
type sequenceHop struct {
	mu    sync.Mutex
	nodes []*chain.Node
	calls int
}

func (h *sequenceHop) Select(context.Context, ...hop.SelectOption) *chain.Node {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := h.nodes[min(h.calls, len(h.nodes)-1)]
	h.calls++
	return n
}

var _ hop.Hop = (*sequenceHop)(nil)

// retryNode builds a node that opts into retries with the given budget and
// codes metadata. An empty codes string leaves the key absent so the default
// applies.
func retryNode(name, addr string, max int, codes string) *chain.Node {
	md := map[string]any{"retry.max": max}
	if codes != "" {
		md["retry.codes"] = codes
	}
	return chain.NewNode(name, addr,
		chain.HTTPNodeOption(&chain.HTTPNodeSettings{FailCodes: chain.FailCodes{429, 5}}),
		chain.MetadataNodeOption(metadata.NewMetadata(md)),
	)
}

// upstreamReply describes how a test upstream answers.
type upstreamReply struct {
	status int
	body   string
	header http.Header
	// read drains the request body and keeps it for assertions. It must stay
	// false for an Expect: 100-continue request: reading the body makes the
	// server answer with an interim 100 Continue first.
	read bool
}

// retryUpstream is an httptest server that answers every request with one
// fixed reply and counts hits.
type retryUpstream struct {
	*httptest.Server

	hits atomic.Int32
	mu   sync.Mutex
	body []byte
}

func newRetryUpstream(t *testing.T, reply upstreamReply) *retryUpstream {
	t.Helper()
	u := &retryUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		if reply.read {
			body, _ := io.ReadAll(r.Body)
			u.mu.Lock()
			u.body = body
			u.mu.Unlock()
		}
		for k, vs := range reply.header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(reply.status)
		io.WriteString(w, reply.body)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *retryUpstream) addr() string { return u.Listener.Addr().String() }

func (u *retryUpstream) received() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return string(u.body)
}

// retryRequest runs one client request through HandleHTTP and returns the
// client-visible status and body plus the single recorded row.
func retryRequest(t *testing.T, h *Sniffer, hh hop.Hop, body string, headers map[string]string, extra ...sniffing.HandleOption) (int, string, xrecorder.HandlerRecorderObject) {
	t.Helper()
	rec := &captureRecorder{}
	h.Recorder = rec
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	opts := []sniffing.HandleOption{
		sniffing.WithService("test-svc"),
		sniffing.WithHop(hh),
		sniffing.WithRecorderObject(&xrecorder.HandlerRecorderObject{}),
		sniffing.WithLog(xlogger.Nop()),
	}
	opts = append(opts, extra...)
	errCh := make(chan error, 1)
	go func() { errCh <- h.HandleHTTP(context.Background(), serverConn, opts...) }()

	req, _ := http.NewRequest(http.MethodPost, "http://upstream.example/v1/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Close = true
	if err := req.Write(clientConn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
	if err != nil {
		t.Fatal(err)
	}
	gotBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	clientConn.Close()
	<-errCh

	if len(rec.data) != 1 {
		t.Fatalf("recorded %d rows, want 1", len(rec.data))
	}
	var ro xrecorder.HandlerRecorderObject
	if err := json.Unmarshal(rec.data[0], &ro); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(gotBody), ro
}

func TestHandleHTTP_RetriesRetryableStatusOnNextNode(t *testing.T) {
	a := newRetryUpstream(t, upstreamReply{status: http.StatusTooManyRequests, body: "slow down", read: true})
	b := newRetryUpstream(t, upstreamReply{status: http.StatusOK, body: "ok", read: true})

	aNode := retryNode("a", a.addr(), 1, "429,5xx")
	bNode := retryNode("b", b.addr(), 1, "429,5xx")
	h := &Sniffer{ReadTimeout: 5 * time.Second}
	hh := &sequenceHop{nodes: []*chain.Node{aNode, bNode}}

	status, body, ro := retryRequest(t, h, hh, `{"m":1}`, nil)

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if body != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
	if got := a.hits.Load(); got != 1 {
		t.Fatalf("first upstream hits = %d, want 1", got)
	}
	if got := b.hits.Load(); got != 1 {
		t.Fatalf("second upstream hits = %d, want 1", got)
	}
	if got := a.received(); got != `{"m":1}` {
		t.Fatalf("first upstream body = %q", got)
	}
	if got := b.received(); got != `{"m":1}` {
		t.Fatalf("second upstream body = %q", got)
	}
	if got := aNode.Marker().Count(); got != 1 {
		t.Fatalf("failed node fail count = %d, want 1", got)
	}
	if ro.Retries != 1 {
		t.Fatalf("recorded retries = %d, want 1", ro.Retries)
	}
	if ro.Node != "b" {
		t.Fatalf("recorded node = %q, want b", ro.Node)
	}
	if ro.HTTP == nil || ro.HTTP.StatusCode != http.StatusOK {
		t.Fatalf("recorded status = %+v, want 200", ro.HTTP)
	}
}

func TestHandleHTTP_NoRetryWithoutRetryMetadata(t *testing.T) {
	a := newRetryUpstream(t, upstreamReply{status: http.StatusTooManyRequests, read: true})
	b := newRetryUpstream(t, upstreamReply{status: http.StatusOK, body: "ok", read: true})

	hh := &sequenceHop{nodes: []*chain.Node{
		chain.NewNode("a", a.addr()),
		chain.NewNode("b", b.addr()),
	}}
	h := &Sniffer{ReadTimeout: 5 * time.Second}

	status, _, ro := retryRequest(t, h, hh, `{"m":1}`, nil)

	if status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", status)
	}
	if got := a.hits.Load(); got != 1 {
		t.Fatalf("first upstream hits = %d, want 1", got)
	}
	if got := b.hits.Load(); got != 0 {
		t.Fatalf("second upstream hits = %d, want 0", got)
	}
	if ro.Retries != 0 {
		t.Fatalf("recorded retries = %d, want 0", ro.Retries)
	}
}

func TestHandleHTTP_RetryBudgetIsBounded(t *testing.T) {
	a := newRetryUpstream(t, upstreamReply{status: http.StatusTooManyRequests, read: true})
	b := newRetryUpstream(t, upstreamReply{status: http.StatusTooManyRequests, read: true})

	hh := &sequenceHop{nodes: []*chain.Node{
		retryNode("a", a.addr(), 2, ""),
		retryNode("b", b.addr(), 2, ""),
	}}
	h := &Sniffer{ReadTimeout: 5 * time.Second}

	status, _, ro := retryRequest(t, h, hh, `{"m":1}`, nil)

	if status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", status)
	}
	if got := a.hits.Load() + b.hits.Load(); got != 3 {
		t.Fatalf("total upstream hits = %d, want 3", got)
	}
	if ro.Retries != 2 {
		t.Fatalf("recorded retries = %d, want 2", ro.Retries)
	}
}

func TestHandleHTTP_RetrySkipsNonRetryableStatus(t *testing.T) {
	a := newRetryUpstream(t, upstreamReply{status: http.StatusBadRequest, read: true})
	b := newRetryUpstream(t, upstreamReply{status: http.StatusOK, body: "ok", read: true})

	hh := &sequenceHop{nodes: []*chain.Node{
		retryNode("a", a.addr(), 1, "429,5xx"),
		retryNode("b", b.addr(), 1, "429,5xx"),
	}}
	h := &Sniffer{ReadTimeout: 5 * time.Second}

	status, _, ro := retryRequest(t, h, hh, `{"m":1}`, nil)

	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if got := b.hits.Load(); got != 0 {
		t.Fatalf("second upstream hits = %d, want 0", got)
	}
	if ro.Retries != 0 {
		t.Fatalf("recorded retries = %d, want 0", ro.Retries)
	}
}

func TestHandleHTTP_RetryMarksNodeWithoutFailCodes(t *testing.T) {
	a := newRetryUpstream(t, upstreamReply{status: http.StatusTooManyRequests, read: true})
	b := newRetryUpstream(t, upstreamReply{status: http.StatusOK, body: "ok", read: true})

	aNode := chain.NewNode("a", a.addr(),
		chain.MetadataNodeOption(metadata.NewMetadata(map[string]any{"retry.max": 1})))
	hh := &sequenceHop{nodes: []*chain.Node{aNode, chain.NewNode("b", b.addr())}}
	h := &Sniffer{ReadTimeout: 5 * time.Second}

	status, _, ro := retryRequest(t, h, hh, `{"m":1}`, nil)

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got := aNode.Marker().Count(); got != 1 {
		t.Fatalf("failed node fail count = %d, want 1", got)
	}
	if ro.Retries != 1 {
		t.Fatalf("recorded retries = %d, want 1", ro.Retries)
	}
}

func TestHandleHTTP_DialFailureRetriesNextNode(t *testing.T) {
	b := newRetryUpstream(t, upstreamReply{status: http.StatusOK, body: "ok", read: true})

	aNode := retryNode("a", "127.0.0.1:1", 1, "429,5xx")
	bNode := retryNode("b", b.addr(), 1, "429,5xx")
	hh := &sequenceHop{nodes: []*chain.Node{aNode, bNode}}
	h := &Sniffer{ReadTimeout: 5 * time.Second}

	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if address == aNode.Addr {
			return nil, io.ErrUnexpectedEOF
		}
		return net.Dial(network, address)
	}

	status, body, ro := retryRequest(t, h, hh, `{"m":1}`, nil, sniffing.WithDial(dial))

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if body != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
	if got := b.hits.Load(); got != 1 {
		t.Fatalf("second upstream hits = %d, want 1", got)
	}
	if got := b.received(); got != `{"m":1}` {
		t.Fatalf("second upstream body = %q", got)
	}
	if got := aNode.Marker().Count(); got != 1 {
		t.Fatalf("unreachable node fail count = %d, want 1", got)
	}
	if ro.Retries != 1 {
		t.Fatalf("recorded retries = %d, want 1", ro.Retries)
	}
}

func TestHandleHTTP_ResponseReadErrorDoesNotRetry(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	b := newRetryUpstream(t, upstreamReply{status: http.StatusOK, body: "ok", read: true})

	hh := &sequenceHop{nodes: []*chain.Node{
		retryNode("a", ln.Addr().String(), 1, "5xx"),
		retryNode("b", b.addr(), 1, "5xx"),
	}}
	h := &Sniffer{ReadTimeout: 5 * time.Second}

	status, _, ro := retryRequest(t, h, hh, `{"m":1}`, nil)

	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", status)
	}
	if got := b.hits.Load(); got != 0 {
		t.Fatalf("second upstream hits = %d, want 0", got)
	}
	if ro.Retries != 0 {
		t.Fatalf("recorded retries = %d, want 0", ro.Retries)
	}
}

func TestHandleHTTP_NoRetryForExpectContinue(t *testing.T) {
	a := newRetryUpstream(t, upstreamReply{status: http.StatusTooManyRequests, read: false})
	b := newRetryUpstream(t, upstreamReply{status: http.StatusOK, body: "ok", read: true})

	hh := &sequenceHop{nodes: []*chain.Node{
		retryNode("a", a.addr(), 1, "429,5xx"),
		retryNode("b", b.addr(), 1, "429,5xx"),
	}}
	h := &Sniffer{ReadTimeout: 5 * time.Second}

	status, _, _ := retryRequest(t, h, hh, `{"m":1}`, map[string]string{"Expect": "100-continue"})

	if status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", status)
	}
	if got := b.hits.Load(); got != 0 {
		t.Fatalf("second upstream hits = %d, want 0", got)
	}
}

func TestHandleHTTP_RetryOverCapForwardsOnce(t *testing.T) {
	old := retryBodyLimit
	retryBodyLimit = 4
	defer func() { retryBodyLimit = old }()

	a := newRetryUpstream(t, upstreamReply{status: http.StatusTooManyRequests, read: true})
	b := newRetryUpstream(t, upstreamReply{status: http.StatusOK, body: "ok", read: true})

	hh := &sequenceHop{nodes: []*chain.Node{
		retryNode("a", a.addr(), 1, "429,5xx"),
		retryNode("b", b.addr(), 1, "429,5xx"),
	}}
	h := &Sniffer{ReadTimeout: 5 * time.Second}

	status, _, _ := retryRequest(t, h, hh, "12345", nil)

	if status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", status)
	}
	if got := a.received(); got != "12345" {
		t.Fatalf("first upstream body = %q, want 12345", got)
	}
	if got := b.hits.Load(); got != 0 {
		t.Fatalf("second upstream hits = %d, want 0", got)
	}
}

func TestHandleHTTP_StreamingSuccessNotRetried(t *testing.T) {
	a := newRetryUpstream(t, upstreamReply{
		status: http.StatusOK,
		body:   "data: {}\n\n",
		header: http.Header{"Content-Type": []string{"text/event-stream"}},
		read:   true,
	})
	b := newRetryUpstream(t, upstreamReply{status: http.StatusOK, body: "ok", read: true})

	hh := &sequenceHop{nodes: []*chain.Node{
		retryNode("a", a.addr(), 1, "5xx"),
		retryNode("b", b.addr(), 1, "5xx"),
	}}
	h := &Sniffer{ReadTimeout: 5 * time.Second}

	status, body, ro := retryRequest(t, h, hh, `{"m":1}`, nil)

	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if body != "data: {}\n\n" {
		t.Fatalf("body = %q", body)
	}
	if got := a.hits.Load(); got != 1 {
		t.Fatalf("first upstream hits = %d, want 1", got)
	}
	if got := b.hits.Load(); got != 0 {
		t.Fatalf("second upstream hits = %d, want 0", got)
	}
	if ro.Retries != 0 {
		t.Fatalf("recorded retries = %d, want 0", ro.Retries)
	}
}

func TestRewriteBodyMetadataIncludesAttempt(t *testing.T) {
	rb := &rewriteBody{ctx: withAttempt(context.Background(), 2), sid: "s", direction: "request", uri: "/u"}
	if got := rb.baseMetadata()[MetaKeyAttempt]; got != 2 {
		t.Fatalf("attempt metadata = %v, want 2", got)
	}
}
