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

func (d *dtlsDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		mtu            = "mtu"
		flightInterval = "flightInterval"
	)

	d.md.mtu = mdutil.GetInt(md, mtu)
	d.md.flightInterval = mdutil.GetDuration(md, flightInterval)
	return
}
