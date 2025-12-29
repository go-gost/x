package masque

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	mdKeyHost             = "host"
	mdKeyKeepAlive        = "keepAlive"
	mdKeyKeepAlivePeriod  = "ttl"
	mdKeyHandshakeTimeout = "handshakeTimeout"
	mdKeyMaxIdleTimeout   = "maxIdleTimeout"
	mdKeyMaxStreams       = "maxStreams"
)

type metadata struct {
	host string

	// QUIC config options
	keepAlivePeriod  time.Duration
	maxIdleTimeout   time.Duration
	handshakeTimeout time.Duration
	maxStreams       int
}

func (d *masqueDialer) parseMetadata(md mdata.Metadata) (err error) {
	d.md.host = mdutil.GetString(md, mdKeyHost)

	if mdutil.GetBool(md, mdKeyKeepAlive) {
		d.md.keepAlivePeriod = mdutil.GetDuration(md, mdKeyKeepAlivePeriod)
		if d.md.keepAlivePeriod <= 0 {
			d.md.keepAlivePeriod = 10 * time.Second
		}
	}
	d.md.handshakeTimeout = mdutil.GetDuration(md, mdKeyHandshakeTimeout)
	d.md.maxIdleTimeout = mdutil.GetDuration(md, mdKeyMaxIdleTimeout)
	d.md.maxStreams = mdutil.GetInt(md, mdKeyMaxStreams)

	return nil
}
