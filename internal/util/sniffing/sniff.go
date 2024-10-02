package sniffing

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net/http"
	"strings"

	dissector "github.com/go-gost/tls-dissector"
)

const (
	ProtoHTTP = "http"
	ProtoTLS  = "tls"
	ProtoSSH  = "ssh"
)

func Sniff(ctx context.Context, r *bufio.Reader) (proto string, err error) {
	hdr, err := r.Peek(dissector.RecordHeaderLen)
	if err != nil {
		return
	}

	// try to sniff TLS traffic
	tlsVersion := binary.BigEndian.Uint16(hdr[1:3])
	if hdr[0] == dissector.Handshake &&
		(tlsVersion >= tls.VersionTLS10 && tlsVersion <= tls.VersionTLS13) {
		return ProtoTLS, nil
	}

	// try to sniff HTTP traffic
	if isHTTP(string(hdr[:])) {
		return ProtoHTTP, nil
	}

	if string(hdr) == "SSH-2" {
		return ProtoSSH, nil
	}

	return
}

func isHTTP(s string) bool {
	return strings.HasPrefix(http.MethodGet, s[:3]) ||
		strings.HasPrefix(http.MethodPost, s[:4]) ||
		strings.HasPrefix(http.MethodPut, s[:3]) ||
		strings.HasPrefix(http.MethodDelete, s) ||
		strings.HasPrefix(http.MethodOptions, s) ||
		strings.HasPrefix(http.MethodPatch, s) ||
		strings.HasPrefix(http.MethodHead, s[:4]) ||
		strings.HasPrefix(http.MethodConnect, s) ||
		strings.HasPrefix(http.MethodTrace, s) ||
		// HTTP/2 connection preface
		// PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
		strings.HasPrefix(s, "PRI *")
}
