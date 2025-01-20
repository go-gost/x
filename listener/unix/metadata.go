package unix

import (
	md "github.com/go-gost/core/metadata"
)

type metadata struct{}

func (l *unixListener) parseMetadata(md md.Metadata) (err error) {
	return
}
