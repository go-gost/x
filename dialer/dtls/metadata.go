package dtls

import (
	mdata "github.com/go-gost/core/metadata"
)

type metadata struct{}

func (d *dtlsDialer) parseMetadata(md mdata.Metadata) (err error) {
	return
}
