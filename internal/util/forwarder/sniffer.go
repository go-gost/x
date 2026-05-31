package forwarder

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"time"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/x/config"
	tls_util "github.com/go-gost/x/internal/util/tls"
	xrecorder "github.com/go-gost/x/recorder"
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

// HandleOptions holds configuration options for sniffing handlers.
type HandleOptions struct {
	service        string
	dial           func(ctx context.Context, network, address string) (net.Conn, error)
	httpKeepalive  bool
	readTimeout    time.Duration
	node           *chain.Node
	hop            hop.Hop
	bypass         bypass.Bypass
	recorderObject *xrecorder.HandlerRecorderObject
	log            logger.Logger
}

// HandleOption configures HandleOptions for sniffing handlers.
type HandleOption func(opts *HandleOptions)

// WithService sets the service name for bypass and selection lookups.
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

// WithHTTPKeepalive enables or disables HTTP keep-alive on the upstream connection.
func WithHTTPKeepalive(keepalive bool) HandleOption {
	return func(opts *HandleOptions) {
		opts.httpKeepalive = keepalive
	}
}

// WithNode sets a pre-resolved chain node to connect to, bypassing hop selection.
func WithNode(node *chain.Node) HandleOption {
	return func(opts *HandleOptions) {
		opts.node = node
	}
}

// WithHop sets the hop used for node selection when routing requests.
func WithHop(h hop.Hop) HandleOption {
	return func(opts *HandleOptions) {
		opts.hop = h
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
	if ho.readTimeout > 0 {
		return ho.readTimeout
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
