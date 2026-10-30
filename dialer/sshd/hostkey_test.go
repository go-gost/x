package sshd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

	"github.com/go-gost/core/dialer"
	xlogger "github.com/go-gost/x/logger"
	xmd "github.com/go-gost/x/metadata"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type testNetDialer struct{}

func (testNetDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

// startSSHServer runs a minimal SSH server that accepts any authentication.
// It is only used to exercise the client-side host key callback.
func startSSHServer(t *testing.T, signer ssh.Signer) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					newCh.Reject(ssh.UnknownChannelType, "not used")
				}
			}()
		}
	}()

	return ln
}

func TestDialHostKeyVerification(t *testing.T) {
	serverSigner := testSigner(t)
	ln := startSSHServer(t, serverSigner)
	addr := ln.Addr().String()

	newDialer := func(t *testing.T, md map[string]any) *sshdDialer {
		t.Helper()
		d := NewDialer(dialer.LoggerOption(xlogger.Nop())).(*sshdDialer)
		require.NoError(t, d.Init(xmd.NewMetadata(md)))
		return d
	}

	t.Run("reject untrusted host key", func(t *testing.T) {
		trusted := testSigner(t)
		d := newDialer(t, map[string]any{
			"handshakeTimeout": "5s",
			"hostKey":          string(ssh.MarshalAuthorizedKey(trusted.PublicKey())),
		})

		conn, err := d.Dial(context.Background(), addr, dialer.NetDialerDialOption(testNetDialer{}))
		require.Error(t, err)
		require.Nil(t, conn)
	})

	t.Run("accept trusted host key", func(t *testing.T) {
		d := newDialer(t, map[string]any{
			"handshakeTimeout": "5s",
			"hostKey":          string(ssh.MarshalAuthorizedKey(serverSigner.PublicKey())),
		})

		conn, err := d.Dial(context.Background(), addr, dialer.NetDialerDialOption(testNetDialer{}))
		require.NoError(t, err)
		require.NotNil(t, conn)
		conn.Close()
	})

	t.Run("explicit insecure opt-in", func(t *testing.T) {
		d := newDialer(t, map[string]any{
			"handshakeTimeout":          "5s",
			"insecureSkipHostKeyVerify": true,
		})

		conn, err := d.Dial(context.Background(), addr, dialer.NetDialerDialOption(testNetDialer{}))
		require.NoError(t, err)
		require.NotNil(t, conn)
		conn.Close()
	})

	t.Run("fail closed without a trusted key", func(t *testing.T) {
		d := NewDialer(dialer.LoggerOption(xlogger.Nop())).(*sshdDialer)
		err := d.Init(xmd.NewMetadata(map[string]any{
			"hostKeyFile": "/nonexistent/known_hosts",
		}))
		require.Error(t, err)
	})
}
