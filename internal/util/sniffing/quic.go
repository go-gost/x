package sniffing

import (
	"encoding/hex"

	dissector "github.com/go-gost/tls-dissector"

	tls_util "github.com/go-gost/x/internal/util/tls"
	xrecorder "github.com/go-gost/x/recorder"
)

// PopulateQUICClientHello sets ro.Proto to ProtoQUIC and populates ro.TLS
// from the parsed QUIC ClientHello. dgram is the raw client datagram (stored
// as hex in ro.TLS.ClientHello). Values are the client-offered ones and may
// be overwritten by PopulateQUICServerHello with negotiated values later.
func PopulateQUICClientHello(dgram []byte, info *dissector.ClientHelloInfo, ro *xrecorder.HandlerRecorderObject) {
	ro.Proto = ProtoQUIC
	ro.TLS = &xrecorder.TLSRecorderObject{
		ServerName:  info.ServerName,
		ClientHello: hex.EncodeToString(dgram),
	}
	if len(info.SupportedProtos) > 0 {
		ro.TLS.Proto = info.SupportedProtos[0]
	}
	if len(info.SupportedVersions) > 0 {
		ro.TLS.Version = tls_util.Version(info.SupportedVersions[0]).String()
	}
	if len(info.CipherSuites) > 0 {
		ro.TLS.CipherSuite = tls_util.CipherSuite(info.CipherSuites[0]).String()
	}
	if len(info.CompressionMethods) > 0 {
		ro.TLS.CompressionMethod = info.CompressionMethods[0]
	}
}

// PopulateQUICServerHello overwrites ro.TLS fields with negotiated values
// from a parsed QUIC ServerHello. ro.TLS must already be set (typically by
// PopulateQUICClientHello).
func PopulateQUICServerHello(sh *dissector.ServerHelloInfo, ro *xrecorder.HandlerRecorderObject) {
	ro.TLS.CipherSuite = tls_util.CipherSuite(sh.CipherSuite).String()
	ro.TLS.Version = tls_util.Version(sh.Version).String()
	ro.TLS.CompressionMethod = sh.CompressionMethod
	if sh.Proto != "" {
		ro.TLS.Proto = sh.Proto
	}
}
