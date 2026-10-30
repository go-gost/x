package sshd

import (
	"fmt"
	"os"
	"time"

	mdata "github.com/go-gost/core/metadata"
	ssh_util "github.com/go-gost/x/internal/util/ssh"
	mdutil "github.com/go-gost/x/metadata/util"
	"github.com/mitchellh/go-homedir"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

type metadata struct {
	handshakeTimeout  time.Duration
	signer            ssh.Signer
	hostKeyCallback   ssh.HostKeyCallback
	keepalive         bool
	keepaliveInterval time.Duration
	keepaliveTimeout  time.Duration
	keepaliveRetries  int

	tcpKeepalive         bool
	tcpKeepaliveIdle     time.Duration
	tcpKeepaliveInterval time.Duration
	tcpKeepaliveCount    int
}

func (d *sshdDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		handshakeTimeout          = "handshakeTimeout"
		privateKeyFile            = "privateKeyFile"
		hostKeyFile               = "hostKeyFile"
		hostKey                   = "hostKey"
		insecureSkipHostKeyVerify = "insecureSkipHostKeyVerify"
		passphrase                = "passphrase"
	)

	if key := mdutil.GetString(md, privateKeyFile); key != "" {
		key, err = homedir.Expand(key)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(key)
		if err != nil {
			return err
		}

		var pp string
		if mdutil.GetBool(md, "passphraseFromKeyring") {
			pp, err = keyring.Get(fmt.Sprintf("SSH %s", key), key)
			if err != nil {
				return fmt.Errorf("unable to get secret(%s) from keyring: %w", key, err)
			}
		} else {
			pp = mdutil.GetString(md, passphrase)
		}
		if pp == "" {
			d.md.signer, err = ssh.ParsePrivateKey(data)
		} else {
			d.md.signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(pp))
		}
		if err != nil {
			return err
		}
	}

	insecure := mdutil.GetBool(md, insecureSkipHostKeyVerify)
	d.md.hostKeyCallback, err = ssh_util.NewHostKeyCallback(
		mdutil.GetString(md, hostKeyFile, "knownHostsFile"),
		mdutil.GetString(md, hostKey),
		insecure,
	)
	if err != nil {
		return err
	}
	if insecure && d.options.Logger != nil {
		d.options.Logger.Warnf("sshd: host key verification is disabled, connections are vulnerable to man-in-the-middle attacks")
	}

	d.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)

	if d.md.keepalive = mdutil.GetBool(md, "keepalive"); d.md.keepalive {
		d.md.keepaliveInterval = mdutil.GetDuration(md, "ttl", "keepalive.interval")
		d.md.keepaliveTimeout = mdutil.GetDuration(md, "keepalive.timeout")
		d.md.keepaliveRetries = mdutil.GetInt(md, "keepalive.retries")
	}

	d.md.tcpKeepalive = mdutil.GetBool(md, "tcp.keepalive")
	d.md.tcpKeepaliveIdle = mdutil.GetDuration(md, "tcp.keepalive.idle")
	d.md.tcpKeepaliveInterval = mdutil.GetDuration(md, "tcp.keepalive.interval")
	d.md.tcpKeepaliveCount = mdutil.GetInt(md, "tcp.keepalive.count")

	return
}
