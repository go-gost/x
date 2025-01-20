package rtcp

import (
	mdata "github.com/go-gost/core/metadata"
)

type metadata struct{}

func (l *rtcpListener) parseMetadata(md mdata.Metadata) (err error) {
	return
}
