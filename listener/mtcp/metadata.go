package mtcp

import (
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/x/internal/util/mux"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultBacklog = 128
)

type metadata struct {
	mptcp   bool
	muxCfg  *mux.Config
	backlog int
}

func (l *mtcpListener) parseMetadata(md md.Metadata) (err error) {
	l.md.mptcp = mdutil.GetBool(md, "mptcp")

	l.md.muxCfg = &mux.Config{
		Version:           mdutil.GetInt(md, "mux.version"),
		KeepAliveInterval: mdutil.GetDuration(md, "mux.keepaliveInterval"),
		KeepAliveDisabled: mdutil.GetBool(md, "mux.keepaliveDisabled"),
		KeepAliveTimeout:  mdutil.GetDuration(md, "mux.keepaliveTimeout"),
		MaxFrameSize:      mdutil.GetInt(md, "mux.maxFrameSize"),
		MaxReceiveBuffer:  mdutil.GetInt(md, "mux.maxReceiveBuffer"),
		MaxStreamBuffer:   mdutil.GetInt(md, "mux.maxStreamBuffer"),
	}
	if l.md.muxCfg.Version == 0 {
		l.md.muxCfg.Version = 2
	}

	l.md.backlog = mdutil.GetInt(md, "backlog")
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	return
}
