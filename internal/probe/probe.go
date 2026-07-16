// Package probe implements liveness probe checkers for node health monitoring.
package probe

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/go-gost/core/chain"
)

// HTTPProber performs an HTTP GET request over an established tunnel connection
// and validates the response status code.
type HTTPProber struct {
	Path           string
	Host           string
	Headers        map[string]string
	ExpectedStatus int
}

func NewHTTPProber(cfg *chain.ProbeConfig) *HTTPProber {
	path := cfg.HTTPPath
	if path == "" {
		path = "/"
	}
	host := cfg.HTTPHost
	if host == "" {
		host = cfg.Addr
	}
	expected := cfg.ExpectedStatus
	if expected == 0 {
		expected = http.StatusOK
	}
	return &HTTPProber{
		Path:           path,
		Host:           host,
		Headers:        cfg.HTTPHeaders,
		ExpectedStatus: expected,
	}
}

// Probe sends an HTTP/1.1 GET request over conn and returns an error if the
// response status does not match ExpectedStatus.
func (p *HTTPProber) Probe(conn net.Conn) error {
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n", p.Path, p.Host)
	for k, v := range p.Headers {
		req += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	req += "Connection: close\r\n\r\n"

	if _, err := fmt.Fprint(conn, req); err != nil {
		return fmt.Errorf("http probe write: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return fmt.Errorf("http probe read: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != p.ExpectedStatus {
		return fmt.Errorf("http probe: expected status %d, got %d", p.ExpectedStatus, resp.StatusCode)
	}
	return nil
}
