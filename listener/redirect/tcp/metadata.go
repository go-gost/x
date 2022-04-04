package tcp

import (
	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	tproxy bool
}

func (l *redirectListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		tproxy = "tproxy"
	)
	l.md.tproxy = mdx.GetBool(md, tproxy)
	return
}
