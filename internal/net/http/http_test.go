package http

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestGetClientIP(t *testing.T) {
	// nil request
	if ip := GetClientIP(nil); ip != nil {
		t.Errorf("expected nil for nil request, got %v", ip)
	}

	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "CF-Connecting-IP takes priority",
			headers:  map[string]string{"CF-Connecting-IP": "1.2.3.4", "X-Forwarded-For": "5.6.7.8", "X-Real-Ip": "9.10.11.12"},
			expected: "1.2.3.4",
		},
		{
			name:     "X-Forwarded-For fallback single",
			headers:  map[string]string{"X-Forwarded-For": "10.0.0.1"},
			expected: "10.0.0.1",
		},
		{
			name:     "X-Forwarded-For fallback with multiple",
			headers:  map[string]string{"X-Forwarded-For": "10.0.0.1, 10.0.0.2, 10.0.0.3"},
			expected: "10.0.0.1",
		},
		{
			name:     "X-Real-Ip fallback",
			headers:  map[string]string{"X-Real-Ip": "172.16.0.1"},
			expected: "172.16.0.1",
		},
		{
			name:     "no headers",
			headers:  map[string]string{},
			expected: "",
		},
		{
			name:     "empty X-Forwarded-For",
			headers:  map[string]string{"X-Forwarded-For": ""},
			expected: "",
		},
		{
			name:     "X-Forwarded-For with leading space",
			headers:  map[string]string{"X-Forwarded-For": " 10.0.0.1, 10.0.0.2"},
			expected: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			got := GetClientIP(req)
			if tt.expected == "" {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
			} else {
				if got == nil || got.String() != tt.expected {
					t.Errorf("expected %s, got %v", tt.expected, got)
				}
			}
		})
	}
}

func TestBody_Read(t *testing.T) {
	data := "hello world, this is a test message"
	reader := io.NopCloser(strings.NewReader(data))

	body := NewBody(reader, 10)
	buf := make([]byte, 5)

	// First read - 5 bytes
	n, err := body.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes, got %d", n)
	}

	// Second read - another 5 bytes (fills record size)
	buf2 := make([]byte, 5)
	n, err = body.Read(buf2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes, got %d", n)
	}

	// Read remaining - record size exceeded, content not recorded
	buf3 := make([]byte, 100)
	n, err = body.Read(buf3)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}

	content := body.Content()
	if len(content) != 10 {
		t.Errorf("content capped at 10, got %d bytes", len(content))
	}

	if body.Length() != int64(len(data)) {
		t.Errorf("expected length %d, got %d", len(data), body.Length())
	}

	if err := body.Close(); err != nil {
		t.Errorf("unexpected error on close: %v", err)
	}
}

func TestBody_ReadLargerThanRecordSize(t *testing.T) {
	// Test the branch where a single read returns more bytes than remaining recordSize
	data := "hello world!"
	reader := io.NopCloser(strings.NewReader(data))

	// recordSize=3, but we read in 8-byte chunks → n(8) > recordSize(3)
	body := NewBody(reader, 3)
	buf := make([]byte, 8)
	n, err := body.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if n != 8 {
		t.Errorf("expected 8 bytes, got %d", n)
	}
	// Content should be capped at 3 bytes (recordSize)
	content := body.Content()
	if len(content) != 3 {
		t.Errorf("expected 3 bytes recorded, got %d: %q", len(content), string(content))
	}
}

func TestBody_NoRecord(t *testing.T) {
	data := "hello world"
	reader := io.NopCloser(strings.NewReader(data))

	body := NewBody(reader, 0)
	buf := make([]byte, 100)
	n, err := body.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}

	if body.Length() != int64(n) {
		t.Errorf("expected length %d, got %d", n, body.Length())
	}

	content := body.Content()
	if len(content) != 0 {
		t.Errorf("expected empty content when recordSize=0, got %v", content)
	}
}

func TestBody_Content(t *testing.T) {
	body := &Body{buf: *bytes.NewBufferString("recorded")}
	content := body.Content()
	if string(content) != "recorded" {
		t.Errorf("expected 'recorded', got '%s'", string(content))
	}
}

func TestBody_Length(t *testing.T) {
	body := &Body{length: 42}
	if body.Length() != 42 {
		t.Errorf("expected 42, got %d", body.Length())
	}
}
