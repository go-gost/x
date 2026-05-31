package unix

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
	// readTimeout is the deadline for reading data from the upstream
	// (the target Unix socket or pipe). It is set on the upstream conn
	// via SetReadDeadline before each sniffing HTTP/TLS read. Also
	// passed to SnifferBuilder for the upstream response header read
	// timeout.
	// 0 or negative defaults to 15s.
	readTimeout time.Duration

	sniffing        bool
	sniffingTimeout time.Duration

	certificate *x509.Certificate
	privateKey  crypto.PrivateKey
	alpn        string
	mitmBypass  bypass.Bypass
}

func (h *unixHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	if h.md.readTimeout <= 0 {
		h.md.readTimeout = 15 * time.Second
	}

	h.md.sniffing = mdutil.GetBool(md, "sniffing")
	h.md.sniffingTimeout = mdutil.GetDuration(md, "sniffing.timeout")

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
