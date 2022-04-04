package tls

import (
	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	host string
}

func (d *obfsTLSDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		host = "host"
	)

	d.md.host = mdx.GetString(md, host)
	return
}
