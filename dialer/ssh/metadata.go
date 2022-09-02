package ssh

import (
	"io/ioutil"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	"golang.org/x/crypto/ssh"
)

type metadata struct {
	handshakeTimeout time.Duration
	signer           ssh.Signer
}

func (d *sshDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		handshakeTimeout = "handshakeTimeout"
		privateKeyFile   = "privateKeyFile"
		passphrase       = "passphrase"
	)

	if key := mdutil.GetString(md, privateKeyFile); key != "" {
		data, err := ioutil.ReadFile(key)
		if err != nil {
			return err
		}

		pp := mdutil.GetString(md, passphrase)
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

	return
}
