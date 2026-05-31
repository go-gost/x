package sniffing

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	tls_util "github.com/go-gost/x/internal/util/tls"
	xrecorder "github.com/go-gost/x/recorder"
)

const (
	// DefaultReadTimeout is the default timeout for reading data from connections.
	DefaultReadTimeout = 30 * time.Second

	// DefaultBodySize is the default HTTP body or websocket frame size to record.
	DefaultBodySize = 64 * 1024 // 64KB
	// MaxBodySize is the maximum HTTP body or websocket frame size to record.
	MaxBodySize = 1024 * 1024 // 1MB
	// DefaultSampleRate is the default websocket sample rate (samples per second).
	DefaultSampleRate = 10.0
)

// DefaultCertPool is the default in-memory certificate pool used for TLS MITM.
var DefaultCertPool = tls_util.NewMemoryCertPool()

// HandleOptions holds configuration options for sniffing handlers.
type HandleOptions struct {
	service string
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
	dialTLS func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error)

	bypass         bypass.Bypass
	recorderObject *xrecorder.HandlerRecorderObject
	log            logger.Logger
}

// HandleOption configures HandleOptions for sniffing handlers.
type HandleOption func(opts *HandleOptions)

// WithService sets the service name for bypass lookups.
func WithService(service string) HandleOption {
	return func(opts *HandleOptions) {
		opts.service = service
	}
}

// WithDial sets the dial function used to establish upstream connections.
func WithDial(dial func(ctx context.Context, network, address string) (net.Conn, error)) HandleOption {
	return func(opts *HandleOptions) {
		opts.dial = dial
	}
}

// WithDialTLS sets the dial function used for TLS-wrapped upstream connections.
func WithDialTLS(dialTLS func(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error)) HandleOption {
	return func(opts *HandleOptions) {
		opts.dialTLS = dialTLS
	}
}

// WithBypass sets the bypass rules for filtering requests by host.
func WithBypass(bypass bypass.Bypass) HandleOption {
	return func(opts *HandleOptions) {
		opts.bypass = bypass
	}
}

// WithRecorderObject sets the recorder object for capturing traffic metadata.
func WithRecorderObject(ro *xrecorder.HandlerRecorderObject) HandleOption {
	return func(opts *HandleOptions) {
		opts.recorderObject = ro
	}
}

// WithLog sets the logger for the handler.
func WithLog(log logger.Logger) HandleOption {
	return func(opts *HandleOptions) {
		opts.log = log
	}
}

// Sniffer handles HTTP and TLS traffic sniffing, recording, and MITM TLS
// termination for protocol-aware forwarding.
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
}

// ClampBodySize returns the effective body capture size from recorder options,
// bounded by [DefaultBodySize, MaxBodySize]. Returns 0 if body recording is
// disabled.
func ClampBodySize(opts *recorder.Options) int {
	if opts == nil || !opts.HTTPBody {
		return 0
	}
	size := opts.MaxBodySize
	if size <= 0 {
		size = DefaultBodySize
	}
	if size > MaxBodySize {
		size = MaxBodySize
	}
	return size
}

// normalizeHost ensures host contains a port component. If host is already
// in host:port form it is returned unchanged; otherwise defaultPort is appended.
func normalizeHost(host, defaultPort string) string {
	if host == "" {
		return host
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		return net.JoinHostPort(strings.Trim(host, "[]"), defaultPort)
	}
	return host
}

// effectiveReadTimeout returns the read timeout from the Sniffer's ReadTimeout,
// falling back to DefaultReadTimeout.
func (h *Sniffer) effectiveReadTimeout() time.Duration {
	if h.ReadTimeout > 0 {
		return h.ReadTimeout
	}
	return DefaultReadTimeout
}
