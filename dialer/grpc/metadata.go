package grpc

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
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

	d.md.insecure = mdutil.GetBool(md, insecure)
	d.md.host = mdutil.GetString(md, host)
	d.md.path = mdutil.GetString(md, path)

	return
}
