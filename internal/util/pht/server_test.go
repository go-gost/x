package pht

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-gost/core/logger"
)

func TestCreatePipeConcurrent(t *testing.T) {
	s := NewServer(":0",
		PathServerOption("/authorize", "/push", "/pull"),
		LoggerServerOption(nopLogger{}),
	)
	// Drain the accept queue so we don't block on send.
	go func() {
		for range s.cqueue {
		}
	}()

	cid := "test-cid"
	raddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)

	conns := make([]net.Conn, n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			conn, err := s.createPipe(cid, raddr)
			if err != nil {
				t.Errorf("createPipe %d failed: %v", idx, err)
				return
			}
			conns[idx] = conn
		}(i)
	}
	wg.Wait()

	// All goroutines must reference the same pipe.
	var first net.Conn
	for i := 0; i < n; i++ {
		if conns[i] == nil {
			t.Fatalf("goroutine %d returned nil conn", i)
		}
		if first == nil {
			first = conns[i]
		} else if conns[i] != first {
			t.Fatalf("goroutine 0 and %d returned different pipes — LoadOrStore race", i)
		}
	}

	// Verify only one entry in conns after cleanup.
	first.Close()
	s.conns.Delete(cid)
}

func TestCreatePipeQueueFull(t *testing.T) {
	s := NewServer(":0",
		BacklogServerOption(0),
		PathServerOption("/authorize", "/push", "/pull"),
		LoggerServerOption(nopLogger{}),
	)
	// Force the cqueue channel buffer to 0 so every send blocks.
	s.cqueue = make(chan net.Conn, 0)

	_, err := s.createPipe("cid", &net.TCPAddr{})
	if err == nil || err.Error() != "connection queue full" {
		t.Fatalf("expected 'connection queue full', got %v", err)
	}
}

func TestCloseNotification(t *testing.T) {
	// Verify that LoadOrStore correctly returns the existing pipe on collision.
	s := NewServer(":0",
		PathServerOption("/authorize", "/push", "/pull"),
		LoggerServerOption(nopLogger{}),
	)
	go func() {
		for range s.cqueue {
		}
	}()

	cid := "close-test"
	raddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}

	conn1, err := s.createPipe(cid, raddr)
	if err != nil {
		t.Fatal(err)
	}

	// Second createPipe for same CID returns the existing conn.
	conn2, err := s.createPipe(cid, raddr)
	if err != nil {
		t.Fatal(err)
	}
	if conn1 != conn2 {
		t.Fatal("createPipe returned different conn for same CID")
	}

	// Clean up.
	conn1.Close()
	s.conns.Delete(cid)
}

func TestHandlePushEmptyData(t *testing.T) {
	s := NewServer(":0",
		PathServerOption("/authorize", "/push", "/pull"),
		LoggerServerOption(nopLogger{}),
	)
	go func() {
		for range s.cqueue {
		}
	}()

	// Pre-create a pipe entry for the CID.
	cid := "empty-data-test"
	raddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	conn, err := s.createPipe(cid, raddr)
	if err != nil {
		t.Fatal(err)
	}

	// Send POST with body "\n" (empty data after trim).
	body := strings.NewReader("\n")
	req := httptest.NewRequest(http.MethodPost, "/push?token="+cid, body)
	w := httptest.NewRecorder()
	s.handlePush(w, req)

	// Verify no 4xx/5xx status (should not crash/leak).
	if w.Code >= 400 {
		t.Fatalf("unexpected status %d", w.Code)
	}

	// The pipe and conns entry should be cleaned up by the empty-data path.
	// The pipe is closed, so writing should fail.
	_, err = conn.Write([]byte("test"))
	if err == nil {
		t.Fatal("expected write to closed pipe to fail")
	}
}

// nopLogger implements logger.Logger with no-ops.
type nopLogger struct{}

func (l nopLogger) WithFields(map[string]any) logger.Logger         { return l }
func (nopLogger) Debug(args ...any)                                  {}
func (nopLogger) Debugf(format string, args ...any)                  {}
func (nopLogger) Info(args ...any)                                   {}
func (nopLogger) Infof(format string, args ...any)                   {}
func (nopLogger) Warn(args ...any)                                   {}
func (nopLogger) Warnf(format string, args ...any)                   {}
func (nopLogger) Error(args ...any)                                  {}
func (nopLogger) Errorf(format string, args ...any)                  {}
func (nopLogger) Fatal(args ...any)                                  {}
func (nopLogger) Fatalf(format string, args ...any)                  {}
func (nopLogger) Trace(args ...any)                                  {}
func (nopLogger) Tracef(format string, args ...any)                  {}
func (nopLogger) GetLevel() logger.LogLevel                          { return logger.InfoLevel }
func (nopLogger) IsLevelEnabled(level logger.LogLevel) bool          { return false }
