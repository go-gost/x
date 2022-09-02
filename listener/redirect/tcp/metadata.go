package tcp

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

type metadata struct {
	tproxy bool
}

func (l *redirectListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		tproxy = "tproxy"
	)
	l.md.tproxy = mdutil.GetBool(md, tproxy)
	return
}
