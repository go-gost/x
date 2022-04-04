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
}

func (d *icmpDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keepAlive        = "keepAlive"
		handshakeTimeout = "handshakeTimeout"
		maxIdleTimeout   = "maxIdleTimeout"
	)

	d.md.handshakeTimeout = mdx.GetDuration(md, handshakeTimeout)

	d.md.keepAlive = mdx.GetBool(md, keepAlive)
	d.md.handshakeTimeout = mdx.GetDuration(md, handshakeTimeout)
	d.md.maxIdleTimeout = mdx.GetDuration(md, maxIdleTimeout)

	return
}
