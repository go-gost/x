package v4

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

type metadata struct {
	readTimeout     time.Duration
	hash            string
	observePeriod   time.Duration
	sniffing        bool
	sniffingTimeout time.Duration
}

func (h *socks4Handler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.readTimeout = mdutil.GetDuration(md, "readTimeout")
	if h.md.readTimeout <= 0 {
		h.md.readTimeout = 15 * time.Second
	}

	h.md.hash = mdutil.GetString(md, "hash")
	h.md.observePeriod = mdutil.GetDuration(md, "observePeriod")

	h.md.sniffing = mdutil.GetBool(md, "sniffing")
	h.md.sniffingTimeout = mdutil.GetDuration(md, "sniffing.timeout")

	return
}
