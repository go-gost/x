package relay

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"math"
	"time"

	"github.com/go-gost/core/bypass"
	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/internal/util/mux"
	mdutil "github.com/go-gost/x/metadata/util"
	"github.com/go-gost/x/registry"
)

type metadata struct {
	readTimeout            time.Duration
	enableBind             bool
	udpBufferSize          int
	noDelay                bool
	hash                   string
	muxCfg                 *mux.Config
	limiterRefreshInterval time.Duration

	observerPeriod       time.Duration
	observerResetTraffic bool

	sniffing                    bool
	sniffingTimeout             time.Duration
	sniffingWebsocket           bool
	sniffingWebsocketSampleRate float64

	certificate *x509.Certificate
	privateKey  crypto.PrivateKey
	alpn        string
	mitmBypass  bypass.Bypass
}

func (h *relayHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	if h.md.readTimeout <= 0 {
		h.md.readTimeout = 15 * time.Second
	}

	h.md.enableBind = mdutil.GetBool(md, "bind")
	h.md.noDelay = mdutil.GetBool(md, "nodelay")

	if bs := mdutil.GetInt(md, "udpBufferSize"); bs > 0 {
		h.md.udpBufferSize = int(math.Min(math.Max(float64(bs), 512), 64*1024))
	} else {
		h.md.udpBufferSize = 4096
	}

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

	h.md.limiterRefreshInterval = mdutil.GetDuration(md, "limiter.refreshInterval")
	if h.md.limiterRefreshInterval == 0 {
		h.md.limiterRefreshInterval = 30 * time.Second
	}
	if h.md.limiterRefreshInterval < time.Second {
		h.md.limiterRefreshInterval = time.Second
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

	return
}
