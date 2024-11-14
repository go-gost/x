package rudp

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultTTL            = 5 * time.Second
	defaultReadBufferSize = 8192
	defaultReadQueueSize  = 1024
	defaultBacklog        = 128
)

type metadata struct {
	ttl                    time.Duration
	readBufferSize         int
	readQueueSize          int
	backlog                int
	limiterRefreshInterval time.Duration
}

func (l *rudpListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		ttl            = "ttl"
		readBufferSize = "readBufferSize"
		readQueueSize  = "readQueueSize"
		backlog        = "backlog"
	)

	l.md.ttl = mdutil.GetDuration(md, ttl)
	if l.md.ttl <= 0 {
		l.md.ttl = defaultTTL
	}
	l.md.readBufferSize = mdutil.GetInt(md, readBufferSize)
	if l.md.readBufferSize <= 0 {
		l.md.readBufferSize = defaultReadBufferSize
	}

	l.md.readQueueSize = mdutil.GetInt(md, readQueueSize)
	if l.md.readQueueSize <= 0 {
		l.md.readQueueSize = defaultReadQueueSize
	}

	l.md.backlog = mdutil.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	l.md.limiterRefreshInterval = mdutil.GetDuration(md, "limiter.refreshInterval")
	if l.md.limiterRefreshInterval == 0 {
		l.md.limiterRefreshInterval = 30 * time.Second
	}
	if l.md.limiterRefreshInterval < time.Second {
		l.md.limiterRefreshInterval = time.Second
	}

	return
}
