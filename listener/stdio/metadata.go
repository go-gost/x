package stdio

import (
	md "github.com/go-gost/core/metadata"
)

type metadata struct {
	// reserved for future options (e.g., timeouts)
}

func (l *stdioListener) parseMetadata(md md.Metadata) (err error) {
	return
}
