package redirect

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	recorderPeriod time.Duration // reports a live session on this interval; 0 = one record per session, written when it ends.

	sniffing        bool
	sniffingTimeout time.Duration
}

func (h *redirectHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.recorderPeriod = mdutil.GetDuration(md, "recorder.period", "recorder.reportPeriod")

	h.md.sniffing = mdutil.GetBool(md, "sniffing")
	h.md.sniffingTimeout = mdutil.GetDuration(md, "sniffing.timeout")

	return
}
