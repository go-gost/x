package sniffing

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/bypass"
	xbypass "github.com/go-gost/x/bypass"
	xcache "github.com/go-gost/x/cache"
	"github.com/go-gost/x/internal/util/httpcache"
	xlogger "github.com/go-gost/x/logger"
	xrecorder "github.com/go-gost/x/recorder"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
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

// dialLog records which upstreams a handler actually reached.
type dialLog struct {
	mu    sync.Mutex
	addrs []string
}

func (d *dialLog) add(addr string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.addrs = append(d.addrs, addr)
}

func (d *dialLog) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// serveOne accepts one connection on a local listener, hands it to HandleHTTP,
// and returns the client side plus the handler's result.
func serveOne(t *testing.T, h *Sniffer, opts ...HandleOption) (net.Conn, <-chan error) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		errCh <- h.HandleHTTP(context.Background(), "tcp", conn, opts...)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })

	return client, errCh
}

func writeRequest(t *testing.T, conn net.Conn, host string, last bool) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if last {
		req.Close = true
	}
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request to %s: %v", host, err)
	}
	return req
}

func readBody(t *testing.T, br *bufio.Reader, req *http.Request) string {
	t.Helper()
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read response for %s: %v", req.Host, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body for %s: %v", req.Host, err)
	}
	return string(body)
}

func expectBypass(t *testing.T, errCh <-chan error) {
	t.Helper()
	select {
	case err := <-errCh:
		if !errors.Is(err, xbypass.ErrBypass) {
			t.Errorf("HandleHTTP returned %v, want %v", err, xbypass.ErrBypass)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HandleHTTP did not refuse the request")
	}
}

// Every request on a connection is authorized against the bypass in effect at
// the time of that request. A check made once at connection setup authorizes
// the first request and nothing after it: a later request can name another
// host, can be answered from the cache without any dial, and can arrive after
// the bypass was reloaded.
func TestHandleHTTP_AuthorizesEveryRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=600")
		w.Write([]byte("from upstream"))
	}))
	defer upstream.Close()

	newSniffer := func(withCache bool) *Sniffer {
		h := &Sniffer{ReadTimeout: 5 * time.Second, Recorder: &noopRecorder{}}
		if withCache {
			h.Cache = httpcache.New(
				xcache.NewMemoryCache(xcache.Options{DefaultTTL: time.Hour, MaxSize: 16}),
				httpcache.Policy{DefaultTTL: time.Hour},
			)
		}
		return h
	}

	start := func(t *testing.T, h *Sniffer, bp *policyBypass) (net.Conn, *bufio.Reader, *dialLog, <-chan error) {
		t.Helper()
		dials := &dialLog{}
		client, errCh := serveOne(t, h,
			WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.add(address)
				return net.Dial("tcp", upstream.Listener.Addr().String())
			}),
			WithBypass(bp),
			WithRecorderObject(&xrecorder.HandlerRecorderObject{}),
			WithLog(xlogger.Nop()),
		)
		return client, bufio.NewReader(client), dials, errCh
	}

	t.Run("first request to a denied host", func(t *testing.T) {
		bp := newPolicyBypass("denied.example:80")
		client, _, dials, errCh := start(t, newSniffer(false), bp)

		writeRequest(t, client, "denied.example", true)
		expectBypass(t, errCh)

		if got := dials.snapshot(); len(got) != 0 {
			t.Errorf("upstream dials = %v, want none", got)
		}
	})

	t.Run("keep-alive request switching to a denied host", func(t *testing.T) {
		bp := newPolicyBypass("denied.example:80")
		client, br, dials, errCh := start(t, newSniffer(false), bp)

		first := writeRequest(t, client, "allowed.example", false)
		if body := readBody(t, br, first); body != "from upstream" {
			t.Fatalf("first body = %q", body)
		}

		writeRequest(t, client, "denied.example", true)
		expectBypass(t, errCh)

		if got := dials.snapshot(); len(got) != 1 || got[0] != "allowed.example:80" {
			t.Errorf("upstream dials = %v, want only allowed.example:80", got)
		}
	})

	t.Run("keep-alive requests to the same allowed host", func(t *testing.T) {
		bp := newPolicyBypass("denied.example:80")
		client, br, dials, errCh := start(t, newSniffer(false), bp)

		for _, last := range []bool{false, true} {
			req := writeRequest(t, client, "allowed.example", last)
			if body := readBody(t, br, req); body != "from upstream" {
				t.Fatalf("body = %q, want the upstream response", body)
			}
		}

		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("HandleHTTP returned %v, want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("HandleHTTP did not return")
		}

		// One upstream connection serves both requests: authorizing every
		// request must not cost a dial per request.
		if got := dials.snapshot(); len(got) != 1 {
			t.Errorf("upstream dials = %v, want exactly one", got)
		}
	})

	t.Run("policy revoked between requests on one connection", func(t *testing.T) {
		bp := newPolicyBypass()
		client, br, dials, errCh := start(t, newSniffer(false), bp)

		first := writeRequest(t, client, "allowed.example", false)
		if body := readBody(t, br, first); body != "from upstream" {
			t.Fatalf("first body = %q", body)
		}

		bp.deny("allowed.example:80") // the phase switch a long connection outlives

		writeRequest(t, client, "allowed.example", true)
		expectBypass(t, errCh)

		if got := dials.snapshot(); len(got) != 1 {
			t.Errorf("upstream dials = %v, want exactly one", got)
		}
	})

	t.Run("cache hit after the policy was revoked", func(t *testing.T) {
		bp := newPolicyBypass()
		client, br, dials, errCh := start(t, newSniffer(true), bp)

		first := writeRequest(t, client, "allowed.example", false)
		if body := readBody(t, br, first); body != "from upstream" {
			t.Fatalf("first body = %q", body)
		}

		bp.deny("allowed.example:80")

		// The response is in the cache, so this request needs no dial. The
		// gate has to refuse it anyway.
		writeRequest(t, client, "allowed.example", true)
		expectBypass(t, errCh)

		if got := dials.snapshot(); len(got) != 1 {
			t.Errorf("upstream dials = %v, want exactly one", got)
		}
	})
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
// so each stream is authorized on its own. Plaintext h2 (prior knowledge) used
// to pass every hostname rule unchecked, and a connection authorized once
// would have carried any later stream.
func TestServeH2_AuthorizesEveryStream(t *testing.T) {
	newHandler := func(bp *policyBypass, tr http.RoundTripper) *h2Handler {
		return &h2Handler{
			transport:      tr,
			recorder:       &noopRecorder{},
			recorderObject: &xrecorder.HandlerRecorderObject{},
			log:            xlogger.Nop(),
			handleOptions:  &HandleOptions{Bypass: bp},
			network:        "tcp",
		}
	}

	serve := func(t *testing.T, h *h2Handler, authority string) int {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "https://"+authority+"/", nil)
		r.Host = authority
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	t.Run("denied authority", func(t *testing.T) {
		tr := &countingTransport{}
		h := newHandler(newPolicyBypass("denied.example:443"), tr)

		if code := serve(t, h, "denied.example"); code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", code, http.StatusForbidden)
		}
		if tr.count() != 0 {
			t.Errorf("upstream round trips = %d, want 0", tr.count())
		}
	})

	t.Run("second stream to a denied authority", func(t *testing.T) {
		tr := &countingTransport{}
		h := newHandler(newPolicyBypass("denied.example:443"), tr)

		if code := serve(t, h, "allowed.example"); code != http.StatusOK {
			t.Fatalf("first stream status = %d, want %d", code, http.StatusOK)
		}
		if code := serve(t, h, "denied.example"); code != http.StatusForbidden {
			t.Errorf("second stream status = %d, want %d", code, http.StatusForbidden)
		}
		if tr.count() != 1 {
			t.Errorf("upstream round trips = %d, want 1", tr.count())
		}
	})

	t.Run("policy revoked between streams", func(t *testing.T) {
		tr := &countingTransport{}
		bp := newPolicyBypass()
		h := newHandler(bp, tr)

		if code := serve(t, h, "allowed.example"); code != http.StatusOK {
			t.Fatalf("first stream status = %d, want %d", code, http.StatusOK)
		}
		bp.deny("allowed.example:443")
		if code := serve(t, h, "allowed.example"); code != http.StatusForbidden {
			t.Errorf("second stream status = %d, want %d", code, http.StatusForbidden)
		}
		if tr.count() != 1 {
			t.Errorf("upstream round trips = %d, want 1", tr.count())
		}
	})
}

// The same property over a real h2c connection, so the test covers the path
// the sniffer actually routes (PRI preface to serveH2) and not just the
// handler in isolation.
func TestHandleHTTP_AuthorizesH2CoverTheWire(t *testing.T) {
	upstream := httptest.NewServer(h2c.NewHandler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("from upstream"))
		}),
		&http2.Server{},
	))
	defer upstream.Close()

	for _, tc := range []struct {
		name       string
		authority  string
		wantStatus int
	}{
		{name: "denied authority", authority: "denied.example", wantStatus: http.StatusForbidden},
		{name: "allowed authority", authority: "allowed.example", wantStatus: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialUpstream := func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("tcp", upstream.Listener.Addr().String())
			}
			h := &Sniffer{ReadTimeout: 5 * time.Second, Recorder: &noopRecorder{}}
			client, errCh := serveOne(t, h,
				WithDial(dialUpstream),
				WithDialTLS(func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
					return dialUpstream(ctx, network, address)
				}),
				WithBypass(newPolicyBypass("denied.example:443")),
				WithRecorderObject(&xrecorder.HandlerRecorderObject{}),
				WithLog(xlogger.Nop()),
			)

			// h2c with prior knowledge: the client writes the HTTP/2 preface
			// with no upgrade, which is what the sniffer routes to serveH2.
			tr := &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
					return client, nil
				},
			}
			defer tr.CloseIdleConnections()

			req, _ := http.NewRequest(http.MethodGet, "http://"+tc.authority+"/", nil)
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Fatalf("h2 round trip: %v", err)
			}
			defer resp.Body.Close()
			io.ReadAll(resp.Body)

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}

			client.Close()
			select {
			case <-errCh:
			case <-time.After(5 * time.Second):
				t.Error("HandleHTTP did not return")
			}
		})
	}
}

// A pattern set the size of a real deny list: exact names, trailing-dot
// duplicates, wildcard families and CIDRs.
func benchPatterns() []string {
	var p []string
	for i := 0; i < 60; i++ {
		p = append(p, fmt.Sprintf("host%d.example.com", i), fmt.Sprintf("host%d.example.com.", i))
	}
	for i := 0; i < 40; i++ {
		p = append(p, fmt.Sprintf("*.family%d.example.org", i), fmt.Sprintf("*mirror%d*", i))
	}
	for i := 0; i < 29; i++ {
		p = append(p, fmt.Sprintf("10.%d.0.0/16", i))
	}
	return p
}

// What authorizing every request costs. The check is a map lookup plus, for a
// host that matches nothing, a scan of the wildcard patterns.
func BenchmarkCheckBypass(b *testing.B) {
	ho := &HandleOptions{Bypass: xbypass.NewBypass(xbypass.MatchersOption(benchPatterns()))}
	ctx := context.Background()

	b.Run("allowed host, full wildcard scan", func(b *testing.B) {
		for b.Loop() {
			if err := ho.CheckBypass(ctx, "tcp", "not-listed.example.net:80"); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("denied host, exact hit", func(b *testing.B) {
		for b.Loop() {
			if err := ho.CheckBypass(ctx, "tcp", "host7.example.com:80"); err == nil {
				b.Fatal("expected a refusal")
			}
		}
	})
}
