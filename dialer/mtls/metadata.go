package mtls

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
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

	d.md.handshakeTimeout = mdx.GetDuration(md, handshakeTimeout)

	d.md.muxKeepAliveDisabled = mdx.GetBool(md, muxKeepAliveDisabled)
	d.md.muxKeepAliveInterval = mdx.GetDuration(md, muxKeepAliveInterval)
	d.md.muxKeepAliveTimeout = mdx.GetDuration(md, muxKeepAliveTimeout)
	d.md.muxMaxFrameSize = mdx.GetInt(md, muxMaxFrameSize)
	d.md.muxMaxReceiveBuffer = mdx.GetInt(md, muxMaxReceiveBuffer)
	d.md.muxMaxStreamBuffer = mdx.GetInt(md, muxMaxStreamBuffer)

	return
}
