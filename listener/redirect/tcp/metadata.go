package tcp

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	tproxy bool
	mptcp  bool
}

func (l *redirectListener) parseMetadata(md mdata.Metadata) (err error) {
	l.md.tproxy = mdutil.GetBool(md, "tproxy")
	l.md.mptcp = mdutil.GetBool(md, "mptcp")

	return
}
