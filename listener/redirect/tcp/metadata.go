package tcp

import (
	mdata "github.com/go-gost/core/metadata"
)

type metadata struct {
	tproxy bool
}

func (l *redirectListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		tproxy = "tproxy"
	)
	l.md.tproxy = mdata.GetBool(md, tproxy)
	return
}
