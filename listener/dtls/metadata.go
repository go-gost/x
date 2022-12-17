package dtls

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

type metadata struct {
	mtu            int
	flightInterval time.Duration
}

func (l *dtlsListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		mtu            = "mtu"
		flightInterval = "flightInterval"
	)

	l.md.mtu = mdutil.GetInt(md, mtu)
	l.md.flightInterval = mdutil.GetDuration(md, flightInterval)

	return nil
}
