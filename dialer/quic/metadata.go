package quic

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	keepAlivePeriod  time.Duration
	maxIdleTimeout   time.Duration
	handshakeTimeout time.Duration

	cipherKey []byte
}

func (d *quicDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keepAlive        = "keepAlive"
		keepAlivePeriod  = "ttl"
		handshakeTimeout = "handshakeTimeout"
		maxIdleTimeout   = "maxIdleTimeout"

		cipherKey = "cipherKey"
	)

	if key := mdx.GetString(md, cipherKey); key != "" {
		d.md.cipherKey = []byte(key)
	}

	if mdx.GetBool(md, keepAlive) {
		d.md.keepAlivePeriod = mdx.GetDuration(md, keepAlivePeriod)
		if d.md.keepAlivePeriod <= 0 {
			d.md.keepAlivePeriod = 10 * time.Second
		}
	}
	d.md.handshakeTimeout = mdx.GetDuration(md, handshakeTimeout)
	d.md.maxIdleTimeout = mdx.GetDuration(md, maxIdleTimeout)

	return
}
