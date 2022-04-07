package http2

import (
	mdata "github.com/go-gost/core/metadata"
)

type metadata struct{}

func (d *http2Dialer) parseMetadata(md mdata.Metadata) (err error) {
	return
}
