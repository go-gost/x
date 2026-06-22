package tcp

import (
	"time"

	md "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	mptcp     bool
	reuseport bool

	keepalive         bool
	keepaliveIdle     time.Duration
	keepaliveInterval time.Duration
	keepaliveCount    int
}

func (l *tcpListener) parseMetadata(md md.Metadata) (err error) {
	l.md.mptcp = mdutil.GetBool(md, "mptcp")
	l.md.reuseport = mdutil.GetBool(md, "reuseport")

	l.md.keepalive = mdutil.GetBool(md, "keepalive")
	l.md.keepaliveIdle = mdutil.GetDuration(md, "keepalive.idle")
	l.md.keepaliveInterval = mdutil.GetDuration(md, "keepalive.interval")
	l.md.keepaliveCount = mdutil.GetInt(md, "keepalive.count")

	return
}
