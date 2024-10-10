package sshd

import (
	"fmt"
	"os"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
	"github.com/mitchellh/go-homedir"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

type metadata struct {
	handshakeTimeout  time.Duration
	signer            ssh.Signer
	keepalive         bool
	keepaliveInterval time.Duration
	keepaliveTimeout  time.Duration
	keepaliveRetries  int
}

func (d *sshdDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		handshakeTimeout = "handshakeTimeout"
		privateKeyFile   = "privateKeyFile"
		passphrase       = "passphrase"
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

	d.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)

	if d.md.keepalive = mdutil.GetBool(md, "keepalive"); d.md.keepalive {
		d.md.keepaliveInterval = mdutil.GetDuration(md, "ttl", "keepalive.interval")
		d.md.keepaliveTimeout = mdutil.GetDuration(md, "keepalive.timeout")
		d.md.keepaliveRetries = mdutil.GetInt(md, "keepalive.retries")
	}
	return
}
