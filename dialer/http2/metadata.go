package http2

import (
	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/internal/util/ech"
)

type metadata struct {
	ech ech.Config
}

func (d *http2Dialer) parseMetadata(md mdata.Metadata) (err error) {
	d.md.ech = ech.FromMetadata(md)
	return
}
