package http

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"net/http"
	"strings"

	"github.com/asaskevich/govalidator"
	"golang.org/x/net/http/httpguts"
)

// decodeServerName decodes a GOST v2 Gost-Target / X-Gost-Target header
// value. The encoding is: base64(CRC32(hostname) + base64(hostname)).
// It verifies the CRC32 checksum before returning the decoded hostname.
func decodeServerName(s string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(b) < 4 {
		return "", errors.New("invalid name")
	}
	v, err := base64.RawURLEncoding.DecodeString(string(b[4:]))
	if err != nil {
		return "", err
	}
	if crc32.ChecksumIEEE(v) != binary.BigEndian.Uint32(b[:4]) {
		return "", errors.New("invalid name")
	}
	return string(v), nil
}

// basicProxyAuth extracts the username and password from an HTTP Basic
// authentication Proxy-Authorization header value. It returns ok=false
// if the value is empty, not a Basic scheme, or not valid base64.
func basicProxyAuth(proxyAuth string) (username, password string, ok bool) {
	if proxyAuth == "" {
		return
	}

	if !strings.HasPrefix(proxyAuth, "Basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(proxyAuth, "Basic "))
	if err != nil {
		return
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return
	}
	return username, password, true
}

// upgradeType returns the upgrade protocol token from an HTTP header.
// It returns "" if the Connection header does not include an "Upgrade"
// token or if the Upgrade header is absent.
func upgradeType(h http.Header) string {
	if !httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") {
		return ""
	}
	return h.Get("Upgrade")
}

// normalizeHostPort ensures a host string includes a port. If the host
// already contains a port, it is returned unchanged. Otherwise the
// defaultPort is appended. IPv6 addresses are correctly handled: bare
// addresses get bracketed by net.JoinHostPort, and bracketed addresses
// are stripped of brackets before re-joining.
func normalizeHostPort(host, defaultPort string) string {
	if _, port, _ := net.SplitHostPort(host); port == "" {
		return net.JoinHostPort(strings.Trim(host, "[]"), defaultPort)
	}
	return host
}

// buildConnectResponse returns the raw bytes of an HTTP 200 Connection
// established response with the given Proxy-Agent header.
func buildConnectResponse(proxyAgent string) []byte {
	return []byte("HTTP/1.1 200 Connection established\r\n" +
		"Proxy-Agent: " + proxyAgent + "\r\n\r\n")
}

// NormalizedRequest holds the parsed target address and network from an
// HTTP proxy request after URL inference, GOST v2 compatibility decoding,
// and host normalisation.
type NormalizedRequest struct {
	Network string // "tcp" or "udp"
	Addr    string // host:port (default port appended when absent)
}

// normalizeRequest extracts the target address and network from an HTTP
// request. It infers the URL scheme when absent, decodes GOST v2
// compatibility headers (Gost-Target, X-Gost-Target), detects the
// transport protocol from X-Gost-Protocol, and normalises the host to
// include a port.
//
// The function mutates req.URL.Scheme and req.Host as side effects so
// that the caller's request reflects the inferred target.
func normalizeRequest(req *http.Request) *NormalizedRequest {
	if !req.URL.IsAbs() {
		host := req.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if govalidator.IsDNSName(host) || net.ParseIP(host) != nil {
			req.URL.Scheme = "http"
		}
	}

	network := req.Header.Get("X-Gost-Protocol")
	if network != "udp" {
		network = "tcp"
	}

	if v := req.Header.Get("Gost-Target"); v != "" {
		if h, err := decodeServerName(v); err == nil {
			req.Host = h
		}
	}
	if v := req.Header.Get("X-Gost-Target"); v != "" {
		if h, err := decodeServerName(v); err == nil {
			req.Host = h
		}
	}

	addr := normalizeHostPort(req.Host, "80")
	return &NormalizedRequest{Network: network, Addr: addr}
}
