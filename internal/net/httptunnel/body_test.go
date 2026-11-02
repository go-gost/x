package httptunnel

import (
	"io"
	"net/http"
	"testing"
)

func TestBodyReplays(t *testing.T) {
	b := NewBody()

	pr1 := b.Reader()
	if pr1 != b.Reader() {
		t.Fatal("Reader returned a different pipe before GetBody")
	}

	pr2, err := b.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	if pr2 == pr1 {
		t.Fatal("GetBody reused the pipe of the previous attempt")
	}

	// The writer follows the body handed out last: writing through it must be
	// readable from the new pipe, not from the old one.
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 3)
		n, _ := io.ReadFull(pr2, buf)
		got <- string(buf[:n])
	}()
	if _, err := b.Writer().Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if s := <-got; s != "two" {
		t.Fatalf("read %q from the new body, want %q", s, "two")
	}

	pr2.Close()
}

func TestNoRedirect(t *testing.T) {
	for _, code := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		req := &http.Request{Response: &http.Response{StatusCode: code}}
		if err := NoRedirect(req, nil); err != http.ErrUseLastResponse {
			t.Errorf("status %d: got %v, want http.ErrUseLastResponse", code, err)
		}
	}
}
