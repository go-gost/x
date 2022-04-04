package ssh

import (
	"io/ioutil"
	"net/url"
	"strings"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
	"golang.org/x/crypto/ssh"
)

type metadata struct {
	handshakeTimeout time.Duration
	user             *url.Userinfo
	signer           ssh.Signer
}

func (d *sshDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		handshakeTimeout = "handshakeTimeout"
		user             = "user"
		privateKeyFile   = "privateKeyFile"
		passphrase       = "passphrase"
	)

	if v := mdx.GetString(md, user); v != "" {
		ss := strings.SplitN(v, ":", 2)
		if len(ss) == 1 {
			d.md.user = url.User(ss[0])
		} else {
			d.md.user = url.UserPassword(ss[0], ss[1])
		}
	}

	if key := mdx.GetString(md, privateKeyFile); key != "" {
		data, err := ioutil.ReadFile(key)
		if err != nil {
			return err
		}

		pp := mdx.GetString(md, passphrase)
		if pp == "" {
			d.md.signer, err = ssh.ParsePrivateKey(data)
		} else {
			d.md.signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(pp))
		}
		if err != nil {
			return err
		}
	}

	d.md.handshakeTimeout = mdx.GetDuration(md, handshakeTimeout)

	return
}
