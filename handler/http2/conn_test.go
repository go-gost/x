package http2

import (
	"bytes"
	"errors"
	"net/http"
	"testing"
)

type testFlusher struct {
	bytes.Buffer
	flushed bool
}

func (f *testFlusher) Flush() {
	f.flushed = true
}

func TestFlushWriter_Write(t *testing.T) {
	t.Run("normal write", func(t *testing.T) {
		var buf bytes.Buffer
		fw := flushWriter{w: &buf}
		n, err := fw.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if n != 5 {
			t.Errorf("n = %d, want 5", n)
		}
		if buf.String() != "hello" {
			t.Errorf("buf = %q, want %q", buf.String(), "hello")
		}
	})

	t.Run("write and flush", func(t *testing.T) {
		tf := &testFlusher{}
		fw := flushWriter{w: tf}
		_, err := fw.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if !tf.flushed {
			t.Error("expected flush after write")
		}
		if tf.String() != "hello" {
			t.Errorf("buf = %q, want %q", tf.String(), "hello")
		}
	})
}

func TestFlushWriter_PanicRecovery(t *testing.T) {
	t.Run("string panic", func(t *testing.T) {
		pw := &panicWriter{panicVal: "boom"}
		fw := flushWriter{w: pw}
		_, err := fw.Write([]byte("data"))
		if err == nil {
			t.Fatal("expected error from panic recovery")
		}
		if err.Error() != "boom" {
			t.Errorf("err = %q, want %q", err.Error(), "boom")
		}
	})

	t.Run("error panic", func(t *testing.T) {
		pw := &panicWriter{panicVal: errors.New("err boom")}
		fw := flushWriter{w: pw}
		_, err := fw.Write([]byte("data"))
		if err == nil {
			t.Fatal("expected error from panic recovery")
		}
		if err.Error() != "err boom" {
			t.Errorf("err = %q, want %q", err.Error(), "err boom")
		}
	})

	t.Run("int panic", func(t *testing.T) {
		pw := &panicWriter{panicVal: 42}
		fw := flushWriter{w: pw}
		_, err := fw.Write([]byte("data"))
		if err == nil {
			t.Fatal("expected error from panic recovery")
		}
		if err.Error() != "42" {
			t.Errorf("err = %q, want %q", err.Error(), "42")
		}
	})
}

type panicWriter struct {
	panicVal any
}

func (w *panicWriter) Write([]byte) (int, error) {
	panic(w.panicVal)
}

func TestFlushWriter_ImplementsHTTPFlusher(t *testing.T) {
	// flushWriter should allow the wrapped value to be used as http.Flusher.
	tf := &testFlusher{}
	fw := flushWriter{w: tf}
	_, err := fw.Write([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if !tf.flushed {
		t.Error("expected Flush() to be called after Write()")
	}
	// Verify that testFlusher is recognized as http.Flusher.
	var _ http.Flusher = tf
}
