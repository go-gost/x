package forwarder

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/bypass"
	xbypass "github.com/go-gost/x/bypass"
	"github.com/go-gost/x/internal/util/sniffing"
	xlogger "github.com/go-gost/x/logger"
	xrecorder "github.com/go-gost/x/recorder"
)

// policyBypass is a blacklist bypass whose rule set can change while a
// connection is open, the way a file-backed bypass changes on reload.
type policyBypass struct {
	mu     sync.RWMutex
	denied map[string]bool
}

func newPolicyBypass(denied ...string) *policyBypass {
	p := &policyBypass{denied: map[string]bool{}}
	for _, addr := range denied {
		p.denied[addr] = true
	}
	return p
}

func (p *policyBypass) deny(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.denied[addr] = true
}

func (p *policyBypass) Contains(_ context.Context, _, addr string, _ ...bypass.Option) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.denied[addr]
}

func (p *policyBypass) IsWhitelist() bool { return false }

// The forwarder checks the bypass while selecting a node, which happens only
// when a new upstream connection is needed. A request answered from the cache,
// and a request that arrives after the bypass was reloaded, both reach the
// upstream without passing that check unless every request is authorized.
func TestHandleHTTP_AuthorizesEveryRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("from upstream"))
	}))
	defer upstream.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	bp := newPolicyBypass()
	h := &Sniffer{Recorder: &noopRecorder{}}

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		errCh <- h.HandleHTTP(context.Background(), conn,
			sniffing.WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("tcp", upstream.Listener.Addr().String())
			}),
			sniffing.WithBypass(bp),
			sniffing.WithRecorderObject(&xrecorder.HandlerRecorderObject{}),
			sniffing.WithLog(xlogger.Nop()),
		)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	br := bufio.NewReader(client)

	first, _ := http.NewRequest(http.MethodGet, "http://allowed.example/", nil)
	if err := first.Write(client); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	resp.Body.Close()

	bp.deny("allowed.example:80") // the reload a long connection outlives

	second, _ := http.NewRequest(http.MethodGet, "http://allowed.example/", nil)
	second.Close = true
	if err := second.Write(client); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, xbypass.ErrBypass) {
			t.Errorf("HandleHTTP returned %v, want %v", err, xbypass.ErrBypass)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HandleHTTP did not refuse the request made after the reload")
	}
}

// countingTransport reports how many requests reached an upstream.
type countingTransport struct {
	mu    sync.Mutex
	calls int
}

func (t *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.calls++
	t.mu.Unlock()
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{},
		Body:          http.NoBody,
		ContentLength: 0,
		Request:       r,
	}, nil
}

func (t *countingTransport) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls
}

// Each HTTP/2 stream carries its own :authority and reaches its own upstream,
// so each stream is authorized on its own.
func TestServeH2_AuthorizesEveryStream(t *testing.T) {
	tr := &countingTransport{}
	bp := newPolicyBypass("denied.example:443")
	h := &h2Handler{
		transport:      tr,
		recorder:       &noopRecorder{},
		recorderObject: &xrecorder.HandlerRecorderObject{},
		log:            xlogger.Nop(),
		handleOptions:  &sniffing.HandleOptions{Bypass: bp},
	}

	serve := func(authority string) int {
		r := httptest.NewRequest(http.MethodGet, "https://"+authority+"/", nil)
		r.Host = authority
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	if code := serve("allowed.example"); code != http.StatusOK {
		t.Fatalf("first stream status = %d, want %d", code, http.StatusOK)
	}
	if code := serve("denied.example"); code != http.StatusForbidden {
		t.Errorf("denied stream status = %d, want %d", code, http.StatusForbidden)
	}

	bp.deny("allowed.example:443")
	if code := serve("allowed.example"); code != http.StatusForbidden {
		t.Errorf("stream after the reload status = %d, want %d", code, http.StatusForbidden)
	}

	if tr.count() != 1 {
		t.Errorf("upstream round trips = %d, want 1", tr.count())
	}
}
