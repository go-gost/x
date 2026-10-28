package utls

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/internal/util/ech"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	handshakeTimeout time.Duration

	keepalive         bool
	keepaliveIdle     time.Duration
	keepaliveInterval time.Duration
	keepaliveCount    int

	fingerprint string

	ech ech.Config
}

func (d *utlsDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		handshakeTimeout = "handshakeTimeout"
		fingerprint      = "fingerprint"
	)

	d.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)

	d.md.keepalive = mdutil.GetBool(md, "keepalive")
	d.md.keepaliveIdle = mdutil.GetDuration(md, "keepalive.idle")
	d.md.keepaliveInterval = mdutil.GetDuration(md, "keepalive.interval")
	d.md.keepaliveCount = mdutil.GetInt(md, "keepalive.count")

	d.md.fingerprint = mdutil.GetString(md, fingerprint)

	d.md.ech = ech.FromMetadata(md)

	return
}
