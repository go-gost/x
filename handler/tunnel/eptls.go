package tunnel

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"time"

	"github.com/go-gost/core/logger"
	dissector "github.com/go-gost/tls-dissector"
	ictx "github.com/go-gost/x/internal/ctx"
	xio "github.com/go-gost/x/internal/io"
	xnet "github.com/go-gost/x/internal/net"
	tls_util "github.com/go-gost/x/internal/util/tls"
	xrecorder "github.com/go-gost/x/recorder"
)

func (ep *entrypoint) handleTLS(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	buf := new(bytes.Buffer)
	clientHello, err := dissector.ParseClientHello(io.TeeReader(conn, buf))
	if err != nil {
		return err
	}

	ro.TLS = &xrecorder.TLSRecorderObject{
		ServerName:  clientHello.ServerName,
		ClientHello: hex.EncodeToString(buf.Bytes()),
	}
	if len(clientHello.SupportedProtos) > 0 {
		ro.TLS.Proto = clientHello.SupportedProtos[0]
	}

	host := clientHello.ServerName
	if host != "" {
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), "443")
		}
		ro.Host = host
	}

	// ctx = xctx.ContextWithClientAddr(ctx, xctx.ClientAddr(ro.RemoteAddr))
	ctx = ictx.ContextWithRecorderObject(ctx, ro)
	ctx = ictx.ContextWithLogger(ctx, log)

	cc, err := ep.dial(ctx, "tcp", host)
	if err != nil {
		return err
	}
	defer cc.Close()

	if _, err := buf.WriteTo(cc); err != nil {
		return err
	}

	xio.SetReadDeadline(cc, time.Now().Add(ep.readTimeout))
	serverHello, err := dissector.ParseServerHello(io.TeeReader(cc, buf))
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

	// xnet.Transport(conn, cc)
	xnet.Pipe(ctx, conn, cc)
	return err
}