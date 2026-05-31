package sni

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/go-gost/core/bypass"
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
	"github.com/go-gost/x/registry"
)

type metadata struct {
	// readTimeout is passed to SnifferBuilder as the timeout for reading
	// upstream response headers during HTTP/TLS sniffing. It is NOT used
	// as a deadline on the initial client connection (unlike socks/ss
	// handlers), because SNI routing has no protocol handshake beyond
	// the TLS ClientHello which is parsed during sniffing.
	// 0 or negative defaults to 15s.
	readTimeout time.Duration
	hash        string

	sniffingWebsocket           bool
	sniffingWebsocketSampleRate float64

	certificate *x509.Certificate
	privateKey  crypto.PrivateKey
	alpn        string
	mitmBypass  bypass.Bypass
}

func (h *sniHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	if h.md.readTimeout <= 0 {
		h.md.readTimeout = 15 * time.Second
	}
	h.md.hash = mdutil.GetString(md, "hash")

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
