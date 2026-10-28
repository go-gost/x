package quic

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/internal/util/ech"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	keepAlivePeriod  time.Duration
	maxIdleTimeout   time.Duration
	handshakeTimeout time.Duration

	ech ech.Config
}

func (d *icmpDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keepAlive        = "keepAlive"
		keepAlivePeriod  = "ttl"
		handshakeTimeout = "handshakeTimeout"
		maxIdleTimeout   = "maxIdleTimeout"
	)

	if md == nil || !md.IsExists(keepAlive) || mdutil.GetBool(md, keepAlive) {
		d.md.keepAlivePeriod = mdutil.GetDuration(md, keepAlivePeriod)
		if d.md.keepAlivePeriod <= 0 {
			d.md.keepAlivePeriod = 10 * time.Second
		}
	}
	d.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)
	d.md.maxIdleTimeout = mdutil.GetDuration(md, maxIdleTimeout)
	if d.md.maxIdleTimeout <= 0 {
		d.md.maxIdleTimeout = 90 * time.Second
	}

	d.md.ech = ech.FromMetadata(md)

	return
}
