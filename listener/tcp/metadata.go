package tcp

import (
	md "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	mptcp bool
}

func (l *tcpListener) parseMetadata(md md.Metadata) (err error) {
	l.md.mptcp = mdutil.GetBool(md, "mptcp")

	return
}
