package quic

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultBacklog = 128
)

type metadata struct {
	keepAlivePeriod  time.Duration
	handshakeTimeout time.Duration
	maxIdleTimeout   time.Duration

	backlog                int
	limiterRefreshInterval time.Duration
}

func (l *icmpListener) parseMetadata(md mdata.Metadata) (err error) {
	l.md.backlog = mdutil.GetInt(md, "backlog")
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	if mdutil.GetBool(md, "keepalive") {
		l.md.keepAlivePeriod = mdutil.GetDuration(md, "ttl")
		if l.md.keepAlivePeriod <= 0 {
			l.md.keepAlivePeriod = 10 * time.Second
		}
	}
	l.md.handshakeTimeout = mdutil.GetDuration(md, "handshakeTimeout")
	l.md.maxIdleTimeout = mdutil.GetDuration(md, "maxIdleTimeout")

	l.md.limiterRefreshInterval = mdutil.GetDuration(md, "limiter.refreshInterval")
	if l.md.limiterRefreshInterval == 0 {
		l.md.limiterRefreshInterval = 30 * time.Second
	}
	if l.md.limiterRefreshInterval < time.Second {
		l.md.limiterRefreshInterval = time.Second
	}

	return
}
