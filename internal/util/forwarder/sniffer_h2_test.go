package forwarder

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/go-gost/core/recorder"
	xlogger "github.com/go-gost/x/logger"
	xrecorder "github.com/go-gost/x/recorder"
)

// fixedResponseTransport answers every request with the same response.
type fixedResponseTransport struct {
	resp *http.Response
}

func (t *fixedResponseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp := *t.resp
	resp.Request = req
	return &resp, nil
}

// slowBodyRoundTripper answers with a body that sends one byte every gap, n times.
type slowBodyRoundTripper struct {
	n   int
	gap time.Duration
}

func (s *slowBodyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < s.n; i++ {
			time.Sleep(s.gap)
			pw.Write([]byte("x"))
		}
		pw.Close()
	}()
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"text/event-stream"}},
		Body:          pr,
		ContentLength: -1,
		Request:       req,
	}, nil
}

func TestH2HandlerServeHTTP_RecordsBodyCopyError(t *testing.T) {
	tests := []struct {
		name     string
		httpBody bool
		cut      bool
	}{
		{name: "complete", httpBody: false, cut: false},
		{name: "complete with body recording", httpBody: true, cut: false},
		{name: "cut", httpBody: false, cut: true},
		{name: "cut with body recording", httpBody: true, cut: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader = strings.NewReader("abcd")
			if tt.cut {
				// The upstream body fails the way it does when the client resets the stream.
				body = io.MultiReader(body, iotest.ErrReader(context.Canceled))
			}

			rec := &captureRecorder{}
			handler := &h2Handler{
				transport: &fixedResponseTransport{
					resp: &http.Response{
						StatusCode: http.StatusOK,
						Header:     http.Header{},
						Body:       io.NopCloser(body),
					},
				},
				recorder:        rec,
				recorderOptions: &recorder.Options{HTTPBody: tt.httpBody, MaxBodySize: 1024},
				recorderObject:  &xrecorder.HandlerRecorderObject{},
				log:             xlogger.Nop(),
			}

			req := httptest.NewRequest("GET", "https://example.com/path", nil)
			req.RequestURI = "/path"
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if len(rec.data) != 1 {
				t.Fatalf("expected 1 recorder event, got %d", len(rec.data))
			}
			var recorded xrecorder.HandlerRecorderObject
			if err := json.Unmarshal(rec.data[0], &recorded); err != nil {
				t.Fatalf("unmarshal recorder event: %v", err)
			}
			if recorded.HTTP == nil || recorded.HTTP.StatusCode != http.StatusOK {
				t.Fatalf("recorded http = %+v, want status %d", recorded.HTTP, http.StatusOK)
			}
			if tt.cut {
				if !strings.Contains(recorded.Err, context.Canceled.Error()) {
					t.Errorf("recorded err = %q, want it to contain %q", recorded.Err, context.Canceled)
				}
			} else if recorded.Err != "" {
				t.Errorf("recorded err = %q, want none", recorded.Err)
			}
			if tt.httpBody && string(recorded.HTTP.Response.Body) != "abcd" {
				t.Errorf("recorded body = %q, want %q", recorded.HTTP.Response.Body, "abcd")
			}
		})
	}
}

func TestH2HandlerServeHTTP_StreamsBody(t *testing.T) {
	tests := []struct {
		name     string
		httpBody bool
	}{
		{name: "without body recording", httpBody: false},
		{name: "with body recording", httpBody: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &h2Handler{
				transport:       &slowBodyRoundTripper{n: 3, gap: 300 * time.Millisecond},
				recorder:        &noopRecorder{},
				recorderOptions: &recorder.Options{HTTPBody: tt.httpBody, MaxBodySize: 1024},
				recorderObject:  &xrecorder.HandlerRecorderObject{},
				log:             xlogger.Nop(),
			}
			srv := httptest.NewUnstartedServer(handler)
			srv.EnableHTTP2 = true
			srv.StartTLS()
			t.Cleanup(srv.Close)

			start := time.Now()
			resp, err := srv.Client().Get(srv.URL + "/sse")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			t.Cleanup(func() { resp.Body.Close() })
			if resp.ProtoMajor != 2 {
				t.Fatalf("proto = %s, want HTTP/2", resp.Proto)
			}
			// The header must not wait for the body, and the first byte must not
			// wait for the body end (900 ms).
			if head := time.Since(start); head > 200*time.Millisecond {
				t.Errorf("header after %s", head)
			}
			buf := make([]byte, 1)
			if _, err := io.ReadFull(resp.Body, buf); err != nil {
				t.Fatalf("read: %v", err)
			}
			if first := time.Since(start); first > 600*time.Millisecond {
				t.Errorf("first byte after %s", first)
			}
			if buf[0] != 'x' {
				t.Errorf("first byte = %q, want %q", buf[0], 'x')
			}
		})
	}
}
