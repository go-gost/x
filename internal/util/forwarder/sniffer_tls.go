package forwarder

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"crypto/x509"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	dissector "github.com/go-gost/tls-dissector"
	xbypass "github.com/go-gost/x/bypass"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/sniffing"
	tls_util "github.com/go-gost/x/internal/util/tls"
	xrecorder "github.com/go-gost/x/recorder"
)

// HandleTLS sniffs and proxies a TLS connection. It parses the ClientHello
// for SNI-based routing, optionally performs MITM TLS termination for HTTP
// content inspection, and records TLS handshake metadata.
func (h *Sniffer) HandleTLS(ctx context.Context, conn net.Conn, opts ...HandleOption) error {
	var ho HandleOptions
	for _, opt := range opts {
		opt(&ho)
	}
	ho.readTimeout = h.effectiveReadTimeout(&ho)

	buf := new(bytes.Buffer)
	clientHello, err := dissector.ParseClientHello(io.TeeReader(conn, buf))
	if err != nil {
		return err
	}

	ro := ho.recorderObject
	ro.TLS = &xrecorder.TLSRecorderObject{
		ServerName:  clientHello.ServerName,
		ClientHello: hex.EncodeToString(buf.Bytes()),
	}
	if len(clientHello.SupportedProtos) > 0 {
		ro.TLS.Proto = clientHello.SupportedProtos[0]
	}

	host := normalizeHost(clientHello.ServerName, "443")
	if host == "" {
		if ho.log != nil {
			ho.log.Debugf("no sni in clienthello from %s", conn.RemoteAddr())
		}
		return errors.New("tls: sni is empty, closing connection")
	}
	ro.Host = host

	if ho.bypass != nil && ho.bypass.Contains(ctx, "tcp", host, bypass.WithService(ho.service)) {
		return xbypass.ErrBypass
	}

	node, cc, err := h.dialTLS(ctx, host, &ho)
	if err != nil {
		return err
	}
	defer cc.Close()
	ho.node = node

	log := ho.log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	log.Debugf("connected to node %s(%s)", node.Name, node.Addr)

	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	if h.Certificate != nil && h.PrivateKey != nil &&
		len(clientHello.SupportedProtos) > 0 && (clientHello.SupportedProtos[0] == "h2" || clientHello.SupportedProtos[0] == "http/1.1") {
		if host == "" {
			host = ro.Host
		}
		if h.MitmBypass == nil || !h.MitmBypass.Contains(ctx, "tcp", host) {
			return h.terminateTLS(ctx, xnet.NewReadWriteConn(io.MultiReader(buf, conn), conn, conn), cc, clientHello, &ho)
		}
	}

	if _, err := buf.WriteTo(cc); err != nil {
		return err
	}

	xio.SetReadDeadline(cc, time.Now().Add(ho.readTimeout))
	serverHello, serverHelloErr := dissector.ParseServerHello(io.TeeReader(cc, buf))
	xio.SetReadDeadline(cc, time.Time{})

	if serverHello != nil {
		ro.TLS.CipherSuite = tls_util.CipherSuite(serverHello.CipherSuite).String()
		ro.TLS.CompressionMethod = serverHello.CompressionMethod
		if serverHello.Proto != "" {
			ro.TLS.Proto = serverHello.Proto
		}
		if serverHello.Version > 0 {
			ro.TLS.Version = tls_util.Version(serverHello.Version).String()
		}
	}

	if buf.Len() > 0 {
		ro.TLS.ServerHello = hex.EncodeToString(buf.Bytes())
	}

	if _, err := buf.WriteTo(conn); err != nil {
		return err
	}

	log.Infof("%s <-> %s", ro.RemoteAddr, ro.Host)
	xnet.Pipe(ctx, conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(ro.Time),
	}).Infof("%s >-< %s", ro.RemoteAddr, ro.Host)

	// If server hello parsing failed, surface the error after proxy completes.
	if serverHelloErr != nil {
		return serverHelloErr
	}
	return nil
}

// resolveTLSNode selects a node for a TLS connection by applying hop selection.
func resolveTLSNode(ctx context.Context, host string, ho *HandleOptions) (node *chain.Node, err error) {
	node = &chain.Node{}
	if ho.hop != nil {
		var clientIP net.IP
		if clientAddr, _ := net.ResolveTCPAddr("tcp", ho.recorderObject.ClientAddr); clientAddr != nil {
			clientIP = clientAddr.IP
		}
		node = ho.hop.Select(ctx,
			hop.ClientIPSelectOption(clientIP),
			hop.HostSelectOption(host),
			hop.ProtocolSelectOption(sniffing.ProtoTLS),
		)
	}
	if node == nil {
		return nil, errors.New("node not available")
	}
	if node.Addr == "" {
		node = &chain.Node{
			Name: node.Name,
			Addr: host,
		}
	}
	return node, nil
}

// dialTLS selects a node and establishes a TLS connection.
func (h *Sniffer) dialTLS(ctx context.Context, host string, ho *HandleOptions) (node *chain.Node, cc net.Conn, err error) {
	dial := ho.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	if node = ho.node; node != nil {
		cc, err = dial(ctx, "tcp", node.Addr)
		return
	}

	node, err = resolveTLSNode(ctx, host, ho)
	if err != nil {
		return
	}

	ro := ho.recorderObject
	addr := node.Addr
	network := "tcp"
	if opts := node.Options(); opts != nil {
		switch opts.Network {
		case "unix":
			network = opts.Network
		default:
			if _, _, splitErr := net.SplitHostPort(addr); splitErr != nil {
				addr += ":443"
			}
		}
	} else {
		if _, _, splitErr := net.SplitHostPort(addr); splitErr != nil {
			addr += ":443"
		}
	}
	ro.Host = addr

	ho.log = ho.log.WithFields(map[string]any{
		"host": host,
		"node": node.Name,
		"dst":  fmt.Sprintf("%s/%s", addr, network),
	})
	ho.log.Debugf("find node for host %s -> %s(%s)", host, node.Name, addr)

	cc, err = dial(ctx, network, addr)
	if err != nil {
		if marker := node.Marker(); marker != nil {
			marker.Mark()
		}
		ho.log.Warnf("connect to node %s(%s) failed: %v", node.Name, node.Addr, err)
		return
	}

	if marker := node.Marker(); marker != nil {
		marker.Reset()
	}

	cc = tlsWrapConn(cc, node.Options().TLS)
	return
}

// terminateTLS performs MITM TLS termination: handshakes with the upstream
// server as a client, then with the downstream client as a server using a
// dynamically generated certificate. The decrypted traffic is then handled
// as HTTP.
func (h *Sniffer) terminateTLS(ctx context.Context, conn, cc net.Conn, clientHello *dissector.ClientHelloInfo, ho *HandleOptions) error {
	ro := ho.recorderObject
	log := ho.log

	nextProtos := clientHello.SupportedProtos
	if h.NegotiatedProtocol != "" {
		nextProtos = []string{h.NegotiatedProtocol}
	}

	cfg := &tls.Config{
		ServerName:   clientHello.ServerName,
		NextProtos:   nextProtos,
		CipherSuites: clientHello.CipherSuites,
	}
	if cfg.ServerName == "" {
		cfg.InsecureSkipVerify = true
	}
	clientConn := tls.Client(cc, cfg)
	if err := clientConn.HandshakeContext(ctx); err != nil {
		return err
	}

	cs := clientConn.ConnectionState()
	ro.TLS.CipherSuite = tls_util.CipherSuite(cs.CipherSuite).String()
	ro.TLS.Proto = cs.NegotiatedProtocol
	ro.TLS.Version = tls_util.Version(cs.Version).String()

	host := cfg.ServerName
	if host == "" {
		if len(cs.PeerCertificates) > 0 {
			host = cs.PeerCertificates[0].Subject.CommonName
		}
		if host == "" {
			host = ro.Host
		}
	}
	if splitHost, _, _ := net.SplitHostPort(host); splitHost != "" {
		host = splitHost
	}

	negotiatedProtocol := cs.NegotiatedProtocol
	if h.NegotiatedProtocol != "" {
		negotiatedProtocol = h.NegotiatedProtocol
	}
	nextProtos = nil
	if negotiatedProtocol != "" {
		nextProtos = []string{negotiatedProtocol}
	}

	// cache the tls server handshake record.
	wb := &bytes.Buffer{}
	conn = xnet.NewReadWriteConn(conn, io.MultiWriter(wb, conn), conn)

	serverConn := tls.Server(conn, &tls.Config{
		NextProtos: nextProtos,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certPool := h.CertPool
			if certPool == nil {
				certPool = DefaultCertPool
			}
			serverName := chi.ServerName
			if serverName == "" {
				serverName = host
			}
			cert, cerr := certPool.Get(serverName)
			if cert != nil {
				pool := x509.NewCertPool()
				pool.AddCert(h.Certificate)
				if _, cerr = cert.Verify(x509.VerifyOptions{
					DNSName: serverName,
					Roots:   pool,
				}); cerr != nil {
					log.Warnf("verify cached certificate for %s: %v", serverName, cerr)
					cert = nil
				}
			}
			if cert == nil {
				cert, cerr = tls_util.GenerateCertificate(serverName, 7*24*time.Hour, h.Certificate, h.PrivateKey)
				certPool.Put(serverName, cert)
			}
			if cerr != nil {
				return nil, cerr
			}

			return &tls.Certificate{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  h.PrivateKey,
			}, nil
		},
	})
	handshakeErr := serverConn.HandshakeContext(ctx)
	if record, _ := dissector.ReadRecord(wb); record != nil {
		wb.Reset()
		record.WriteTo(wb)
		ro.TLS.ServerHello = hex.EncodeToString(wb.Bytes())
	}
	if handshakeErr != nil {
		return handshakeErr
	}

	opts := []HandleOption{
		WithDial(func(ctx context.Context, network, address string) (net.Conn, error) {
			return clientConn, nil
		}),
		WithHTTPKeepalive(true),
		WithNode(ho.node),
		WithBypass(ho.bypass),
		WithRecorderObject(ro),
		WithLog(log),
	}
	return h.HandleHTTP(ctx, serverConn, opts...)
}
