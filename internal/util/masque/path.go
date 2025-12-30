package masque

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

const (
	// WellKnownPath is the well-known path prefix for MASQUE UDP proxying
	WellKnownPath = "/.well-known/masque/udp/"
)

var (
	ErrInvalidPath = errors.New("masque: invalid path template")
	ErrInvalidPort = errors.New("masque: invalid port number")
)

// ParseMasquePath parses a MASQUE UDP proxy path template.
// The expected format is: /.well-known/masque/udp/{host}/{port}/
// Returns the host and port extracted from the path.
func ParseMasquePath(path string) (host string, port int, err error) {
	if !strings.HasPrefix(path, WellKnownPath) {
		return "", 0, ErrInvalidPath
	}

	remainder := strings.TrimPrefix(path, WellKnownPath)
	remainder = strings.TrimSuffix(remainder, "/")

	parts := strings.Split(remainder, "/")
	if len(parts) != 2 {
		return "", 0, ErrInvalidPath
	}

	host = parts[0]
	if host == "" {
		return "", 0, ErrInvalidPath
	}

	// URL decode the host in case it contains percent-encoded characters
	host, err = url.PathUnescape(host)
	if err != nil {
		return "", 0, ErrInvalidPath
	}

	port, err = strconv.Atoi(parts[1])
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, ErrInvalidPort
	}

	return host, port, nil
}

// BuildMasquePath constructs a MASQUE UDP proxy path from host and port.
func BuildMasquePath(host string, port int) string {
	// URL encode the host in case it contains special characters (like IPv6 addresses)
	encodedHost := url.PathEscape(host)
	return WellKnownPath + encodedHost + "/" + strconv.Itoa(port) + "/"
}
