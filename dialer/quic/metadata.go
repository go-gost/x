package quic

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	keepAlive        time.Duration
	maxIdleTimeout   time.Duration
	handshakeTimeout time.Duration

	cipherKey []byte
}

func (d *quicDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keepAlive        = "keepAlive"
		handshakeTimeout = "handshakeTimeout"
		maxIdleTimeout   = "maxIdleTimeout"

		cipherKey = "cipherKey"
	)

	d.md.handshakeTimeout = mdx.GetDuration(md, handshakeTimeout)

	if key := mdx.GetString(md, cipherKey); key != "" {
		d.md.cipherKey = []byte(key)
	}

	d.md.keepAlive = mdx.GetDuration(md, keepAlive)
	d.md.handshakeTimeout = mdx.GetDuration(md, handshakeTimeout)
	d.md.maxIdleTimeout = mdx.GetDuration(md, maxIdleTimeout)

	return
}
