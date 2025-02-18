package tap

import (
	"math"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	MaxMessageSize = math.MaxUint16
)

type metadata struct {
	key string
}

func (h *tapHandler) parseMetadata(md mdata.Metadata) (err error) {
	const (
		key = "key"
	)

	h.md.key = mdutil.GetString(md, key)
	return
}
