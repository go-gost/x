package http

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	"github.com/go-gost/core/bypass"
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
	"github.com/go-gost/x/registry"
)

const (
	defaultRealm      = "gost"
	defaultProxyAgent = "gost/3.0"
)

// metadata holds all configuration parsed from the handler's metadata map.
// Fields are populated by parseMetadata and read throughout the handler's
// request-processing methods.
type metadata struct {
	readTimeout time.Duration // deadline for upstream response headers (http.Transport.ResponseHeaderTimeout); 0=15s default, negative=disabled
	idleTimeout time.Duration // idle read deadline per Pipe direction during CONNECT/forwarding; 0 or negative = disabled
	keepalive   bool          // enable HTTP keep-alive on the upstream transport
	compression bool          // enable HTTP compression on the upstream transport

	probeResistance *probeResistance // decoy response config for auth failures (nil = disabled)
	enableUDP       bool             // allow UDP relay over HTTP
	udpBufferSize   int              // UDP relay buffer size in bytes

	header         http.Header // additional response headers added to every proxy response
	hash           string      // hash strategy for hop selection ("host" or empty)
	authBasicRealm string      // custom realm for Basic auth 407 responses
	proxyAgent     string      // Proxy-Agent header value; default "gost/3.0"

	observerPeriod       time.Duration // stats reporting interval; default 5s, min 1s
	observerResetTraffic bool          // reset traffic counters after each observation

	sniffing                    bool          // enable protocol sniffing on CONNECT tunnels
	sniffingTimeout             time.Duration // deadline for the initial sniff read
	sniffingWebsocket           bool          // enable WebSocket frame recording
	sniffingWebsocketSampleRate float64       // max frames recorded per second

	certificate *x509.Certificate  // MITM CA certificate (for TLS decryption)
	privateKey  crypto.PrivateKey  // MITM CA private key
	alpn        string             // ALPN protocol to negotiate during MITM
	mitmBypass  bypass.Bypass      // bypass rules that skip MITM decryption

	limiterRefreshInterval time.Duration // traffic limiter cache refresh interval
	limiterCleanupInterval time.Duration // traffic limiter cache cleanup interval
}

// parseMetadata reads all configuration values from the metadata map into
// the handler's metadata struct. It applies defaults for readTimeout (15s),
// observerPeriod (5s, min 1s), and proxyAgent ("gost/3.0"). MITM TLS is
// enabled when both mitm.certFile and mitm.keyFile are provided.
func (h *httpHandler) parseMetadata(md mdata.Metadata) error {
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	if h.md.readTimeout == 0 {
		h.md.readTimeout = 15 * time.Second
	}
	if h.md.readTimeout < 0 {
		h.md.readTimeout = 0
	}

	h.md.idleTimeout = mdutil.GetDuration(md, "idleTimeout")
	if h.md.idleTimeout < 0 {
		h.md.idleTimeout = 0
	}

	if m := mdutil.GetStringMapString(md, "http.header", "header"); len(m) > 0 {
		hd := http.Header{}
		for k, v := range m {
			hd.Add(k, v)
		}
		h.md.header = hd
	}

	h.md.keepalive = mdutil.GetBool(md, "http.keepalive", "keepalive")
	h.md.compression = mdutil.GetBool(md, "http.compression", "compression")

	// probeResist format: "type:value" (e.g. "code:404", "web:example.com",
	// "host:192.168.1.1:80", "file:/var/www/index.html").
	if pr := mdutil.GetString(md, "probeResist", "probe_resist"); pr != "" {
		if ss := strings.SplitN(pr, ":", 2); len(ss) == 2 {
			h.md.probeResistance = &probeResistance{
				Type:  ss[0],
				Value: ss[1],
				Knock: mdutil.GetString(md, "knock"),
			}
		}
	}
	h.md.enableUDP = mdutil.GetBool(md, "udp")
	h.md.udpBufferSize = mdutil.GetInt(md, "udp.bufferSize", "udpBufferSize")
	h.md.hash = mdutil.GetString(md, "hash")
	h.md.authBasicRealm = mdutil.GetString(md, "authBasicRealm")

	h.md.observerPeriod = mdutil.GetDuration(md, "observePeriod", "observer.period", "observer.observePeriod")
	if h.md.observerPeriod == 0 {
		h.md.observerPeriod = 5 * time.Second
	}
	if h.md.observerPeriod < time.Second {
		h.md.observerPeriod = time.Second
	}

	h.md.observerResetTraffic = mdutil.GetBool(md, "observer.resetTraffic")

	h.md.proxyAgent = mdutil.GetString(md, "http.proxyAgent", "proxyAgent")
	if h.md.proxyAgent == "" {
		h.md.proxyAgent = defaultProxyAgent
	}

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

	return nil
}

// probeResistance configures a decoy response that hides the proxy from
// unauthorised clients. When authentication fails, instead of returning
// 407 Proxy-Auth-Required, the handler returns a fake response that makes
// the port appear to run a different service.
type probeResistance struct {
	Type  string // strategy: "code", "web", "host", or "file"
	Value string // strategy-specific parameter (status code, URL, address, path)
	Knock string // optional comma-separated hostnames; probe resistance only fires when the request hostname matches none of them
}
