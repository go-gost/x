package mtls

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

type metadata struct {
	handshakeTimeout time.Duration

	muxKeepAliveDisabled bool
	muxKeepAliveInterval time.Duration
	muxKeepAliveTimeout  time.Duration
	muxMaxFrameSize      int
	muxMaxReceiveBuffer  int
	muxMaxStreamBuffer   int
}

func (d *mtlsDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		handshakeTimeout = "handshakeTimeout"

		muxKeepAliveDisabled = "muxKeepAliveDisabled"
		muxKeepAliveInterval = "muxKeepAliveInterval"
		muxKeepAliveTimeout  = "muxKeepAliveTimeout"
		muxMaxFrameSize      = "muxMaxFrameSize"
		muxMaxReceiveBuffer  = "muxMaxReceiveBuffer"
		muxMaxStreamBuffer   = "muxMaxStreamBuffer"
	)

	d.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)

	d.md.muxKeepAliveDisabled = mdutil.GetBool(md, muxKeepAliveDisabled)
	d.md.muxKeepAliveInterval = mdutil.GetDuration(md, muxKeepAliveInterval)
	d.md.muxKeepAliveTimeout = mdutil.GetDuration(md, muxKeepAliveTimeout)
	d.md.muxMaxFrameSize = mdutil.GetInt(md, muxMaxFrameSize)
	d.md.muxMaxReceiveBuffer = mdutil.GetInt(md, muxMaxReceiveBuffer)
	d.md.muxMaxStreamBuffer = mdutil.GetInt(md, muxMaxStreamBuffer)

	return
}
