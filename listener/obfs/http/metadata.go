package http

import (
	"net/http"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	header http.Header
}

func (l *obfsListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		header = "header"
	)

	if mm := mdx.GetStringMapString(md, header); len(mm) > 0 {
		hd := http.Header{}
		for k, v := range mm {
			hd.Add(k, v)
		}
		l.md.header = hd
	}
	return
}
