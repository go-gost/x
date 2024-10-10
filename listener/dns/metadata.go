package dns

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultBacklog = 128
)

type metadata struct {
	mode           string
	readBufferSize int
	readTimeout    time.Duration
	writeTimeout   time.Duration
	backlog        int
	mptcp          bool
}

func (l *dnsListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		backlog        = "backlog"
		mode           = "mode"
		readBufferSize = "readBufferSize"
		readTimeout    = "readTimeout"
		writeTimeout   = "writeTimeout"
	)

	l.md.mode = mdutil.GetString(md, mode)
	l.md.readBufferSize = mdutil.GetInt(md, readBufferSize)
	l.md.readTimeout = mdutil.GetDuration(md, readTimeout)
	l.md.writeTimeout = mdutil.GetDuration(md, writeTimeout)

	l.md.backlog = mdutil.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}
	l.md.mptcp = mdutil.GetBool(md, "mptcp")

	return
}
