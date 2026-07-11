package utls

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	xctx "github.com/go-gost/x/ctx"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/net/proxyproto"
	"github.com/go-gost/x/registry"
	utls "github.com/refraction-networking/utls"
)

func init() {
	registry.DialerRegistry().Register("utls", NewDialer)
}

type utlsDialer struct {
	md      metadata
	log     logger.Logger
	options dialer.Options
}

func NewDialer(opts ...dialer.Option) dialer.Dialer {
	options := dialer.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &utlsDialer{
		log:     options.Logger,
		options: options,
	}
}

func (d *utlsDialer) Init(md md.Metadata) (err error) {
	return d.parseMetadata(md)
}

func (d *utlsDialer) Dial(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
	var options dialer.DialOptions
	for _, opt := range opts {
		opt(&options)
	}

	conn, err := options.Dialer.Dial(ctx, "tcp", addr)
	if err != nil {
		d.log.Error(err)
	}

	if d.md.keepalive {
		xnet.ApplyKeepalive(conn, net.KeepAliveConfig{
			Enable:   true,
			Idle:     d.md.keepaliveIdle,
			Interval: d.md.keepaliveInterval,
			Count:    d.md.keepaliveCount,
		})
	}

	conn = proxyproto.WrapClientConn(
		d.options.ProxyProtocol,
		xctx.SrcAddrFromContext(ctx),
		xctx.DstAddrFromContext(ctx),
		conn)

	return conn, err
}

// Handshake implements dialer.Handshaker.
func (d *utlsDialer) Handshake(ctx context.Context, conn net.Conn, options ...dialer.HandshakeOption) (net.Conn, error) {
	if d.md.handshakeTimeout > 0 {
		conn.SetDeadline(time.Now().Add(d.md.handshakeTimeout))
		defer conn.SetDeadline(time.Time{})
	}

	clientHelloID, ok := GetClientHelloID(d.md.fingerprint)
	if ok {
		d.log.Debugf("utls handshake with fingerprint: %s", d.md.fingerprint)
		utlsCfg := toUTLSConfig(d.options.TLSConfig)
		uconn := utls.UClient(conn, utlsCfg, clientHelloID)
		if err := uconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return uconn, nil
	}

	// fingerprint not set, empty, "golang", or unknown: fall through to
	// standard crypto/tls.
	if d.md.fingerprint != "" {
		d.log.Warnf("unknown utls fingerprint: %s, falling back to standard TLS", d.md.fingerprint)
	}
	tlsConn := tls.Client(conn, d.options.TLSConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// toUTLSConfig builds an equivalent utls.Config from a standard crypto/tls.Config.
//
// utls.Config is a distinct type from crypto/tls.Config and its field offsets
// diverge from ServerName onward (crypto/tls added fields utls does not have),
// so a direct (*utls.Config)(unsafe.Pointer(...)) reinterprets memory and reads
// garbage for ServerName/InsecureSkipVerify — which is what broke TLS
// verification for this dialer. We copy fields explicitly instead.
//
// Fields whose types differ between the two packages (Certificate, ClientAuth,
// CurveID, RenegotiationSupport, ConnectionState, the Get* callbacks,
// ClientSessionCache) are converted or skipped: the config path that feeds this
// dialer (LoadClientConfig) never populates the Get*/ClientSessionCache
// callbacks, so skipping them is safe here.
func toUTLSConfig(c *tls.Config) *utls.Config {
	if c == nil {
		return &utls.Config{}
	}

	uc := &utls.Config{
		Rand:                        c.Rand,
		Time:                        c.Time,
		Certificates:                toUTLSCertificates(c.Certificates),
		RootCAs:                     c.RootCAs,
		NextProtos:                  c.NextProtos,
		ServerName:                  c.ServerName,
		ClientAuth:                  utls.ClientAuthType(c.ClientAuth),
		ClientCAs:                   c.ClientCAs,
		InsecureSkipVerify:          c.InsecureSkipVerify,
		CipherSuites:                c.CipherSuites,
		PreferServerCipherSuites:    c.PreferServerCipherSuites,
		SessionTicketsDisabled:      c.SessionTicketsDisabled,
		CurvePreferences:            toUTLSCurveIDs(c.CurvePreferences),
		DynamicRecordSizingDisabled: c.DynamicRecordSizingDisabled,
		Renegotiation:               utls.RenegotiationSupport(c.Renegotiation),
		KeyLogWriter:                c.KeyLogWriter,
		MinVersion:                  c.MinVersion,
		MaxVersion:                  c.MaxVersion,
		VerifyPeerCertificate:       c.VerifyPeerCertificate,
	}

	if c.VerifyConnection != nil {
		vc := c.VerifyConnection
		uc.VerifyConnection = func(cs utls.ConnectionState) error {
			return vc(tls.ConnectionState{
				PeerCertificates: cs.PeerCertificates,
			})
		}
	}

	return uc
}

func toUTLSCertificates(certs []tls.Certificate) []utls.Certificate {
	if certs == nil {
		return nil
	}
	out := make([]utls.Certificate, len(certs))
	for i, c := range certs {
		sa := make([]utls.SignatureScheme, len(c.SupportedSignatureAlgorithms))
		for j, s := range c.SupportedSignatureAlgorithms {
			sa[j] = utls.SignatureScheme(s)
		}
		out[i] = utls.Certificate{
			Certificate:                  c.Certificate,
			PrivateKey:                   c.PrivateKey,
			SupportedSignatureAlgorithms: sa,
			OCSPStaple:                   c.OCSPStaple,
			SignedCertificateTimestamps:  c.SignedCertificateTimestamps,
			Leaf:                         c.Leaf,
		}
	}
	return out
}

// utlsCurves maps the crypto/tls curve IDs that utls understands.
//
// crypto/tls and utls use separate CurveID enumerations. Go has added
// post-quantum hybrid curves (X25519MLKEM768, SecP256r1MLKEM768,
// SecP384r1MLKEM1024) whose numeric IDs utls does not recognise, so a
// blind utls.CurveID(id) cast turns them into unsupported curve IDs and
// aborts the handshake with "CurvePreferences includes unsupported curve".
// We keep only the curves utls can actually use and drop the rest; if none
// survive, return nil so utls falls back to the fingerprint's defaults.
var utlsCurves = map[tls.CurveID]utls.CurveID{
	tls.X25519:   utls.X25519,
	tls.CurveP256: utls.CurveP256,
	tls.CurveP384: utls.CurveP384,
	tls.CurveP521: utls.CurveP521,
}

func toUTLSCurveIDs(ids []tls.CurveID) []utls.CurveID {
	if len(ids) == 0 {
		return nil
	}
	out := make([]utls.CurveID, 0, len(ids))
	for _, id := range ids {
		if c, ok := utlsCurves[id]; ok {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
