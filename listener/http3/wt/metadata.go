package wt

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultPath    = "/wt"
	defaultBacklog = 128
)

type metadata struct {
	path    string
	backlog int

	// QUIC config options
	keepAlivePeriod  time.Duration
	maxIdleTimeout   time.Duration
	handshakeTimeout time.Duration
	maxStreams       int
}

func (l *wtListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		keepAlive        = "keepalive"
		keepAlivePeriod  = "ttl"
		handshakeTimeout = "handshakeTimeout"
		maxIdleTimeout   = "maxIdleTimeout"
		maxStreams       = "maxStreams"

		backlog = "backlog"
	)

	l.md.path = mdutil.GetString(md, "wt.path", "path")
	if l.md.path == "" {
		l.md.path = defaultPath
	}

	l.md.backlog = mdutil.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	if mdutil.GetBool(md, keepAlive) {
		l.md.keepAlivePeriod = mdutil.GetDuration(md, keepAlivePeriod)
		if l.md.keepAlivePeriod <= 0 {
			l.md.keepAlivePeriod = 10 * time.Second
		}
	}
	l.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)
	l.md.maxIdleTimeout = mdutil.GetDuration(md, maxIdleTimeout)
	l.md.maxStreams = mdutil.GetInt(md, maxStreams)

	return
}
