package relay

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/go-gost/core/bypass"
	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/internal/util/mux"
	mdutil "github.com/go-gost/x/metadata/util"
	"github.com/go-gost/x/registry"
)

// metadata holds the relay handler configuration parsed from the generic Metadata map.
type metadata struct {
	// readTimeout is the deadline for reading the initial relay.Request handshake.
	// Cleared immediately after the handshake, so it does not affect data transfer.
	// Also passed to SnifferBuilder for upstream response header read timeout.
	// Default: 15s (0 or negative falls back to 15s).
	readTimeout time.Duration

	// udpBufferSize is the buffer size (in bytes) for UDP datagram relay.
	// Config keys: "udp.bufferSize", "udpBufferSize".
	udpBufferSize int

	// enableBind controls whether CmdBind is allowed.
	// Disabled by default; set "bind: true" in config to enable.
	enableBind bool

	// noDelay controls whether the relay.Response header is sent immediately.
	// When enabled, each write is an independent relay frame (low-latency).
	// When disabled, the response header is buffered in wbuf and merged with
	// the first data write.
	noDelay bool

	// hash specifies the consistent-hashing source. Currently supports "host",
	// which uses the target address as the hash source for sticky sessions.
	hash string

	// muxCfg is the multiplexing session configuration, used only in BIND mode
	// to upgrade the client connection to a mux session.
	muxCfg *mux.Config

	// observerPeriod is the stats event polling interval.
	// Default: 5s, minimum: 1s.
	// Config keys: "observePeriod", "observer.period", "observer.observePeriod".
	observerPeriod time.Duration

	// observerResetTraffic controls whether traffic counters are reset after
	// each poll. When true, reported traffic is incremental; when false, cumulative.
	observerResetTraffic bool

	// sniffing enables protocol sniffing. When enabled, the handler detects
	// the traffic protocol (HTTP/TLS) after connection establishment and
	// selects the corresponding processing path (e.g. MITM decryption).
	sniffing bool

	// sniffingTimeout is the read deadline during sniffing.
	sniffingTimeout time.Duration

	// sniffingWebsocket enables WebSocket upgrade detection within sniffed HTTP.
	sniffingWebsocket bool

	// sniffingWebsocketSampleRate controls the sampling rate for WebSocket
	// traffic recording (0.0 ~ 1.0).
	sniffingWebsocketSampleRate float64

	// certificate is the CA certificate used for MITM decryption.
	certificate *x509.Certificate

	// privateKey is the private key paired with the MITM certificate.
	privateKey crypto.PrivateKey

	// alpn is the TLS ALPN protocol list for MITM decryption.
	alpn string

	// mitmBypass is an allow/deny list of hostnames that skip MITM decryption.
	mitmBypass bypass.Bypass

	// limiterRefreshInterval is the traffic limiter cache refresh interval.
	limiterRefreshInterval time.Duration

	// limiterCleanupInterval is the traffic limiter cache cleanup interval.
	limiterCleanupInterval time.Duration
}

// parseMetadata extracts typed configuration from the generic Metadata map.
//
// Rules:
//   - Uses mdutil Get* helpers which support multiple fallback key names.
//   - Numeric durations are treated as seconds; string durations use time.ParseDuration.
//   - Unset or invalid values fall back to sensible defaults.
func (h *relayHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	if h.md.readTimeout <= 0 {
		h.md.readTimeout = 15 * time.Second
	}

	h.md.udpBufferSize = mdutil.GetInt(md, "udp.bufferSize", "udpBufferSize")
	h.md.enableBind = mdutil.GetBool(md, "bind")
	h.md.noDelay = mdutil.GetBool(md, "nodelay")
	h.md.hash = mdutil.GetString(md, "hash")

	h.md.muxCfg = &mux.Config{
		Version:           mdutil.GetInt(md, "mux.version"),
		KeepAliveInterval: mdutil.GetDuration(md, "mux.keepaliveInterval"),
		KeepAliveDisabled: mdutil.GetBool(md, "mux.keepaliveDisabled"),
		KeepAliveTimeout:  mdutil.GetDuration(md, "mux.keepaliveTimeout"),
		MaxFrameSize:      mdutil.GetInt(md, "mux.maxFrameSize"),
		MaxReceiveBuffer:  mdutil.GetInt(md, "mux.maxReceiveBuffer"),
		MaxStreamBuffer:   mdutil.GetInt(md, "mux.maxStreamBuffer"),
	}

	h.md.observerPeriod = mdutil.GetDuration(md, "observePeriod", "observer.period", "observer.observePeriod")
	if h.md.observerPeriod == 0 {
		h.md.observerPeriod = 5 * time.Second
	}
	if h.md.observerPeriod < time.Second {
		h.md.observerPeriod = time.Second
	}

	h.md.observerResetTraffic = mdutil.GetBool(md, "observer.resetTraffic")

	h.md.sniffing = mdutil.GetBool(md, "sniffing")
	h.md.sniffingTimeout = mdutil.GetDuration(md, "sniffing.timeout")
	h.md.sniffingWebsocket = mdutil.GetBool(md, "sniffing.websocket")
	h.md.sniffingWebsocketSampleRate = mdutil.GetFloat(md, "sniffing.websocket.sampleRate")

	certFile := mdutil.GetString(md, "mitm.certFile", "mitm.caCertFile")
	keyFile := mdutil.GetString(md, "mitm.keyFile", "mitm.caKeyFile")
	if certFile != "" && keyFile != "" {
		tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
		h.md.certificate, err = x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			return err
		}
		h.md.privateKey = tlsCert.PrivateKey
	}
	h.md.alpn = mdutil.GetString(md, "mitm.alpn")
	h.md.mitmBypass = registry.BypassRegistry().Get(mdutil.GetString(md, "mitm.bypass"))

	h.md.limiterRefreshInterval = mdutil.GetDuration(md, "limiter.refreshInterval")
	h.md.limiterCleanupInterval = mdutil.GetDuration(md, "limiter.cleanupInterval")

	return
}