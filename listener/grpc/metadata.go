package grpc

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

const (
	defaultBacklog = 128
)

type metadata struct {
	backlog  int
	insecure bool
	path     string
}

func (l *grpcListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		backlog  = "backlog"
		insecure = "grpcInsecure"
		path     = "path"
	)

	l.md.backlog = mdutil.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	l.md.insecure = mdutil.GetBool(md, insecure)
	l.md.path = mdutil.GetString(md, path)
	return
}
