package http2

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultBacklog = 128
)

type metadata struct {
	backlog int
	mptcp   bool

	keepalive         bool
	keepaliveIdle     time.Duration
	keepaliveInterval time.Duration
	keepaliveCount    int
}

func (l *http2Listener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		backlog = "backlog"
	)

	l.md.backlog = mdutil.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}
	l.md.mptcp = mdutil.GetBool(md, "mptcp")

	l.md.keepalive = mdutil.GetBool(md, "keepalive")
	l.md.keepaliveIdle = mdutil.GetDuration(md, "keepalive.idle")
	l.md.keepaliveInterval = mdutil.GetDuration(md, "keepalive.interval")
	l.md.keepaliveCount = mdutil.GetInt(md, "keepalive.count")

	return
}
