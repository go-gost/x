package h2

import (
	"net/http"

	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/internal/util/ech"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	host   string
	path   string
	header http.Header

	ech ech.Config
}

func (d *h2Dialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		host   = "host"
		path   = "path"
		header = "header"
	)

	d.md.host = mdutil.GetString(md, host)
	d.md.path = mdutil.GetString(md, path)
	if m := mdutil.GetStringMapString(md, header); len(m) > 0 {
		h := http.Header{}
		for k, v := range m {
			h.Add(k, v)
		}
		d.md.header = h
	}
	d.md.ech = ech.FromMetadata(md)
	return
}
