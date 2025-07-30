package udp

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultTTL            = 5 * time.Second
	defaultReadBufferSize = 4096
	defaultReadQueueSize  = 128
	defaultBacklog        = 128
)

type metadata struct {
	readBufferSize int
	readQueueSize  int
	backlog        int
	keepalive      bool
	ttl            time.Duration
}

func (l *udpListener) parseMetadata(md mdata.Metadata) (err error) {
	l.md.backlog = mdutil.GetInt(md, "backlog")
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	l.md.keepalive = mdutil.GetBool(md, "keepalive")
	l.md.ttl = mdutil.GetDuration(md, "ttl", "keepalive.ttl")
	if l.md.ttl <= 0 {
		l.md.ttl = defaultTTL
	}
	l.md.readBufferSize = mdutil.GetInt(md, "readBufferSize", "udp.bufferSize")
	if l.md.readBufferSize <= 0 {
		l.md.readBufferSize = defaultReadBufferSize
	}

	l.md.readQueueSize = mdutil.GetInt(md, "readQueueSize", "recvQueueSize")
	if l.md.readQueueSize <= 0 {
		l.md.readQueueSize = defaultReadQueueSize
	}

	return
}
