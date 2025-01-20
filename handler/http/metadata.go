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

type metadata struct {
	readTimeout     time.Duration
	keepalive       bool
	compression     bool
	probeResistance *probeResistance
	enableUDP       bool
	header          http.Header
	hash            string
	authBasicRealm  string
	proxyAgent      string

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

	limiterRefreshInterval time.Duration
	limiterCleanupInterval time.Duration
}

func (h *httpHandler) parseMetadata(md mdata.Metadata) error {
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	if h.md.readTimeout <= 0 {
		h.md.readTimeout = 15 * time.Second
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

type probeResistance struct {
	Type  string
	Value string
	Knock string
}
