package forwarder

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/x/config"
	"github.com/go-gost/x/internal/util/httpcache"
	"github.com/go-gost/x/internal/util/sniffing"
	tls_util "github.com/go-gost/x/internal/util/tls"
)

const (
	// defaultBodySize is the default HTTP body or websocket frame size to record.
	defaultBodySize = 64 * 1024 // 64KB
	// maxBodySize is the maximum HTTP body or websocket frame size to record.
	maxBodySize = 1024 * 1024 // 1MB
)

// DefaultReadTimeout is the default timeout for reading data from connections.
const DefaultReadTimeout = 30 * time.Second

// DefaultCertPool is the default in-memory certificate pool used for TLS MITM.
var DefaultCertPool = tls_util.NewMemoryCertPool()

// HandleOptions aliases sniffing.HandleOptions, the unified option set shared
// by the sniffing and forwarder Sniffer implementations.
type HandleOptions = sniffing.HandleOptions

// HandleOption configures HandleOptions for sniffing handlers.
type HandleOption = sniffing.HandleOption

// Sniffer handles HTTP and TLS traffic sniffing, recording, and MITM TLS
// termination for protocol-aware forwarding. It can intercept HTTP requests,
// perform hop/node selection, apply bypass rules, rewrite URLs and response
// bodies, and terminate TLS for content inspection.
type Sniffer struct {
	Websocket           bool
	WebsocketSampleRate float64

	Recorder        recorder.Recorder
	RecorderOptions *recorder.Options

	// MITM TLS termination
	Certificate        *x509.Certificate
	PrivateKey         crypto.PrivateKey
	NegotiatedProtocol string
	CertPool           tls_util.CertPool
	MitmBypass         bypass.Bypass

	// ReadTimeout is the deadline for reading the upstream response
	// headers during HTTP sniffing (http.ReadResponse) and the TLS
	// ServerHello during TLS sniffing. This timeout is applied once
	// per request/response pair in the HTTP keep-alive loop and cleared
	// after each response is received. It does NOT affect the client
	// connection or the response body transfer.
	// Default: DefaultReadTimeout (30s) if not set.
	ReadTimeout time.Duration

	// Cache, when non-nil, caches upstream HTTP responses. It is shared across
	// connections (built once per service), so all connections referencing the
	// same named cache share one store.
	Cache *httpcache.Cache
}

// clampBodySize returns the effective body capture size from recorder options,
// bounded by [defaultBodySize, maxBodySize]. Returns 0 if body recording is
// disabled.
func clampBodySize(opts *recorder.Options) int {
	if opts == nil || !opts.HTTPBody {
		return 0
	}
	size := opts.MaxBodySize
	if size <= 0 {
		size = defaultBodySize
	}
	if size > maxBodySize {
		size = maxBodySize
	}
	return size
}

// normalizeHost ensures host contains a port component. If host is already
// in host:port form it is returned unchanged; otherwise defaultPort is appended.
// IPv6 addresses are handled correctly (brackets are stripped before joining).
func normalizeHost(host, defaultPort string) string {
	if host == "" {
		return host
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(strings.Trim(host, "[]"), defaultPort)
	}
	return host
}

// effectiveReadTimeout returns the read timeout from options, falling back to
// the Sniffer's ReadTimeout, then to DefaultReadTimeout.
func (h *Sniffer) effectiveReadTimeout(ho *HandleOptions) time.Duration {
	if ho.ReadTimeout > 0 {
		return ho.ReadTimeout
	}
	if h.ReadTimeout > 0 {
		return h.ReadTimeout
	}
	return DefaultReadTimeout
}

// tlsWrapConn wraps cc in a TLS client using the node's TLS settings.
func tlsWrapConn(cc net.Conn, tlsSettings *chain.TLSNodeSettings) net.Conn {
	if tlsSettings == nil {
		return cc
	}
	cfg := &tls.Config{
		ServerName:         tlsSettings.ServerName,
		InsecureSkipVerify: !tlsSettings.Secure,
	}
	tls_util.SetTLSOptions(cfg, &config.TLSOptions{
		MinVersion:   tlsSettings.Options.MinVersion,
		MaxVersion:   tlsSettings.Options.MaxVersion,
		CipherSuites: tlsSettings.Options.CipherSuites,
		ALPN:         tlsSettings.Options.ALPN,
	})
	return tls.Client(cc, cfg)
}
