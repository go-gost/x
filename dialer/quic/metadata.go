package quic

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	keepAlive        bool
	maxIdleTimeout   time.Duration
	handshakeTimeout time.Duration

	cipherKey []byte
	host      string
}

func (d *quicDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keepAlive        = "keepAlive"
		handshakeTimeout = "handshakeTimeout"
		maxIdleTimeout   = "maxIdleTimeout"

		cipherKey = "cipherKey"
		host      = "host"
	)

	d.md.handshakeTimeout = mdx.GetDuration(md, handshakeTimeout)

	if key := mdx.GetString(md, cipherKey); key != "" {
		d.md.cipherKey = []byte(key)
	}

	d.md.keepAlive = mdx.GetBool(md, keepAlive)
	d.md.handshakeTimeout = mdx.GetDuration(md, handshakeTimeout)
	d.md.maxIdleTimeout = mdx.GetDuration(md, maxIdleTimeout)

	d.md.host = mdx.GetString(md, host)
	return
}
