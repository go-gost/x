package http

import (
	"net/http"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	header http.Header
	mptcp  bool
}

func (l *obfsListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		header = "header"
	)

	if mm := mdutil.GetStringMapString(md, header); len(mm) > 0 {
		hd := http.Header{}
		for k, v := range mm {
			hd.Add(k, v)
		}
		l.md.header = hd
	}

	l.md.mptcp = mdutil.GetBool(md, "mptcp")

	return
}
