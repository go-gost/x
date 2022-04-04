package mtls

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

const (
	defaultBacklog = 128
)

type metadata struct {
	muxKeepAliveDisabled bool
	muxKeepAliveInterval time.Duration
	muxKeepAliveTimeout  time.Duration
	muxMaxFrameSize      int
	muxMaxReceiveBuffer  int
	muxMaxStreamBuffer   int

	backlog int
}

func (l *mtlsListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		backlog = "backlog"

		muxKeepAliveDisabled = "muxKeepAliveDisabled"
		muxKeepAliveInterval = "muxKeepAliveInterval"
		muxKeepAliveTimeout  = "muxKeepAliveTimeout"
		muxMaxFrameSize      = "muxMaxFrameSize"
		muxMaxReceiveBuffer  = "muxMaxReceiveBuffer"
		muxMaxStreamBuffer   = "muxMaxStreamBuffer"
	)

	l.md.backlog = mdx.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	l.md.muxKeepAliveDisabled = mdx.GetBool(md, muxKeepAliveDisabled)
	l.md.muxKeepAliveInterval = mdx.GetDuration(md, muxKeepAliveInterval)
	l.md.muxKeepAliveTimeout = mdx.GetDuration(md, muxKeepAliveTimeout)
	l.md.muxMaxFrameSize = mdx.GetInt(md, muxMaxFrameSize)
	l.md.muxMaxReceiveBuffer = mdx.GetInt(md, muxMaxReceiveBuffer)
	l.md.muxMaxStreamBuffer = mdx.GetInt(md, muxMaxStreamBuffer)

	return
}
