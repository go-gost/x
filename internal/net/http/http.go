package http

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
)

// GetClientIP extracts the client IP from the request, checking CF-Connecting-IP,
// X-Forwarded-For, and X-Real-Ip headers in that order.
func GetClientIP(req *http.Request) net.IP {
	if req == nil {
		return nil
	}
	// cloudflare CDN
	sip := req.Header.Get("CF-Connecting-IP")
	if sip == "" {
		ss := strings.Split(req.Header.Get("X-Forwarded-For"), ",")
		if len(ss) > 0 && ss[0] != "" {
			sip = strings.TrimSpace(ss[0])
		}
	}
	if sip == "" {
		sip = req.Header.Get("X-Real-Ip")
	}

	return net.ParseIP(sip)
}

// Body wraps an io.ReadCloser with size-limited recording of the data read.
type Body struct {
	r          io.ReadCloser
	buf        bytes.Buffer
	length     int64
	recordSize int
}

// NewBody creates a Body that reads from r and records up to maxRecordSize bytes.
func NewBody(r io.ReadCloser, maxRecordSize int) *Body {
	p := &Body{
		r:          r,
		recordSize: maxRecordSize,
	}

	return p
}

func (p *Body) Read(b []byte) (n int, err error) {
	n, err = p.r.Read(b)
	p.length += int64(n)

	if p.recordSize > 0 {
		b = b[:n]
		if n > p.recordSize {
			b = b[:p.recordSize]
		}
		p.buf.Write(b)
		p.recordSize -= len(b)
	}

	return
}

func (p *Body) Close() error {
	return p.r.Close()
}

// Content returns the recorded content.
func (p *Body) Content() []byte {
	return p.buf.Bytes()
}

// Length returns the total number of bytes read from the underlying reader.
func (p *Body) Length() int64 {
	return p.length
}
