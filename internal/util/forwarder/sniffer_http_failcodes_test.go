package forwarder

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
	xlogger "github.com/go-gost/x/logger"
	xrecorder "github.com/go-gost/x/recorder"

	"github.com/go-gost/x/internal/util/sniffing"
)

// httpFailCodesNode is a helper for the failCodes marker tests: it builds a
// node whose HTTP settings mark the given status codes as failures.
func httpFailCodesNode(name, addr string, codes ...int) *chain.Node {
	return chain.NewNode(name, addr,
		chain.HTTPNodeOption(&chain.HTTPNodeSettings{
			FailCodes: chain.FailCodes(codes),
		}),
	)
}

// doSnifferRequest runs one HTTP request through HandleHTTP against node and
// returns the response status. Each call uses a fresh client connection, which
// is what a real client does when the upstream keep-alive is off.
func doSnifferRequest(t *testing.T, h *Sniffer, node *chain.Node, extra ...sniffing.HandleOption) int {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	opts := []sniffing.HandleOption{
		sniffing.WithService("test-svc"),
		sniffing.WithHop(&mockHop{nodes: []*chain.Node{node}}),
		sniffing.WithRecorderObject(&xrecorder.HandlerRecorderObject{}),
		sniffing.WithLog(xlogger.Nop()),
	}
	opts = append(opts, extra...)

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.HandleHTTP(context.Background(), serverConn, opts...)
	}()

	req, _ := http.NewRequest(http.MethodGet, "http://upstream.example/", nil)
	req.Close = true
	if err := req.Write(clientConn); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	clientConn.Close()
	<-errCh

	return resp.StatusCode
}

// TestHandleHTTP_FailCodesAccumulateAcrossRequests locks in the fix for
// maxFails > 1: a failCodes response must leave the failure count in place
// across requests. Before the fix, dial() reset the node marker on every
// successful connect, so each request restarted from zero and the count could
// never exceed one.
func TestHandleHTTP_FailCodesAccumulateAcrossRequests(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	node := httpFailCodesNode("backend", upstream.Listener.Addr().String(), 5)
	h := &Sniffer{ReadTimeout: 5 * time.Second}

	for i := 1; i <= 2; i++ {
		if got := doSnifferRequest(t, h, node); got != http.StatusInternalServerError {
			t.Fatalf("request %d status = %d, want 500", i, got)
		}
		if got := node.Marker().Count(); got != int64(i) {
			t.Fatalf("after request %d fail count = %d, want %d", i, got, i)
		}
	}

	// A successful response is the recovery signal: it clears the count that
	// the failing requests accumulated.
	fail.Store(false)
	if got := doSnifferRequest(t, h, node); got != http.StatusOK {
		t.Fatalf("recovery request status = %d, want 200", got)
	}
	if got := node.Marker().Count(); got != 0 {
		t.Fatalf("fail count after a successful response = %d, want 0", got)
	}
}

// TestHandleHTTP_DialFailureRecoversOnResponse proves the recovery half of the
// marker lifecycle is preserved: a node marked by a failed connect still clears
// its count on the next successful response (or after failTimeout), it just no
// longer clears it on the bare connect.
func TestHandleHTTP_DialFailureRecoversOnResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	node := httpFailCodesNode("backend", upstream.Listener.Addr().String(), 5)
	h := &Sniffer{ReadTimeout: 5 * time.Second}

	var attempts atomic.Int32
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if attempts.Add(1) == 1 {
			return nil, io.ErrUnexpectedEOF
		}
		return net.Dial("tcp", upstream.Listener.Addr().String())
	}

	if got := doSnifferRequest(t, h, node, sniffing.WithDial(dial)); got != http.StatusServiceUnavailable {
		t.Fatalf("first request status = %d, want 503", got)
	}
	if got := node.Marker().Count(); got != 1 {
		t.Fatalf("fail count after a dial failure = %d, want 1", got)
	}

	if got := doSnifferRequest(t, h, node, sniffing.WithDial(dial)); got != http.StatusOK {
		t.Fatalf("recovery request status = %d, want 200", got)
	}
	if got := node.Marker().Count(); got != 0 {
		t.Fatalf("fail count after a successful response = %d, want 0", got)
	}
}
