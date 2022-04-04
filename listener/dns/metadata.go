package dns

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
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
}

func (l *dnsListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		backlog        = "backlog"
		mode           = "mode"
		readBufferSize = "readBufferSize"
		readTimeout    = "readTimeout"
		writeTimeout   = "writeTimeout"
	)

	l.md.mode = mdx.GetString(md, mode)
	l.md.readBufferSize = mdx.GetInt(md, readBufferSize)
	l.md.readTimeout = mdx.GetDuration(md, readTimeout)
	l.md.writeTimeout = mdx.GetDuration(md, writeTimeout)

	l.md.backlog = mdx.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	return
}
