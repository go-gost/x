package http2

import (
	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

const (
	defaultBacklog = 128
)

type metadata struct {
	backlog int
}

func (l *http2Listener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		backlog = "backlog"
	)

	l.md.backlog = mdx.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}
	return
}
