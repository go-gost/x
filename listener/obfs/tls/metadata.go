package tls

import (
	md "github.com/go-gost/core/metadata"
)

type metadata struct {
}

func (l *obfsListener) parseMetadata(md md.Metadata) (err error) {
	return
}
