package h2

import (
	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	host string
	path string
}

func (d *h2Dialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		host = "host"
		path = "path"
	)

	d.md.host = mdx.GetString(md, host)
	d.md.path = mdx.GetString(md, path)

	return
}
