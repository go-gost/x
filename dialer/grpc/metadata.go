package grpc

import (
	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

type metadata struct {
	insecure bool
	host     string
	path     string
}

func (d *grpcDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		insecure = "grpcInsecure"
		host     = "host"
		path     = "path"
	)

	d.md.insecure = mdx.GetBool(md, insecure)
	d.md.host = mdx.GetString(md, host)
	d.md.path = mdx.GetString(md, path)

	return
}
