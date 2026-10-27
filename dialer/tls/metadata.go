package tls

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	handshakeTimeout time.Duration

	keepalive         bool
	keepaliveIdle     time.Duration
	keepaliveInterval time.Duration
	keepaliveCount    int

	ech            bool
	echDoH         string
	echTimeout     time.Duration
	echTTL         time.Duration
	echFallback    bool
	echDoHInsecure bool
}

func (d *tlsDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		handshakeTimeout = "handshakeTimeout"
	)

	d.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)

	d.md.keepalive = mdutil.GetBool(md, "keepalive")
	d.md.keepaliveIdle = mdutil.GetDuration(md, "keepalive.idle")
	d.md.keepaliveInterval = mdutil.GetDuration(md, "keepalive.interval")
	d.md.keepaliveCount = mdutil.GetInt(md, "keepalive.count")

	d.md.ech = mdutil.GetBool(md, "ech")
	d.md.echDoH = mdutil.GetString(md, "ech.doh")
	d.md.echTimeout = mdutil.GetDuration(md, "ech.timeout")
	d.md.echTTL = mdutil.GetDuration(md, "ech.ttl")
	d.md.echFallback = mdutil.GetBool(md, "ech.fallback")
	d.md.echDoHInsecure = mdutil.GetBool(md, "ech.dohInsecure")

	return
}
