package tun

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultKeepAlivePeriod = 10 * time.Second
	defaultBufferSize      = 4096
)

type metadata struct {
	bufferSize      int
	keepAlivePeriod time.Duration
	passphrase      string
	p2p             bool
}

func (h *tunHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.bufferSize = mdutil.GetInt(md, "tun.bufsize", "bufsize", "buffersize")
	if h.md.bufferSize <= 0 {
		h.md.bufferSize = defaultBufferSize
	}

	if mdutil.GetBool(md, "tun.keepalive", "keepalive") {
		h.md.keepAlivePeriod = mdutil.GetDuration(md, "tun.ttl", "ttl")
		if h.md.keepAlivePeriod <= 0 {
			h.md.keepAlivePeriod = defaultKeepAlivePeriod
		}
	}

	h.md.passphrase = mdutil.GetString(md, "tun.token", "token", "passphrase")
	h.md.p2p = mdutil.GetBool(md, "tun.p2p", "p2p")
	return
}
