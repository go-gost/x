package mws

import (
	"net/http"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
	"github.com/go-gost/x/internal/util/mux"
)

const (
	defaultPath            = "/ws"
	defaultKeepalivePeriod = 15 * time.Second
)

type metadata struct {
	host string
	path string

	handshakeTimeout  time.Duration
	readHeaderTimeout time.Duration
	readBufferSize    int
	writeBufferSize   int
	enableCompression bool

	header            http.Header
	keepaliveInterval time.Duration
	muxCfg            *mux.Config
}

func (d *mwsDialer) parseMetadata(md mdata.Metadata) (err error) {
	d.md.host = mdutil.GetString(md, "ws.host", "host")
	d.md.path = mdutil.GetString(md, "ws.path", "path")
	if d.md.path == "" {
		d.md.path = defaultPath
	}

	d.md.muxCfg = &mux.Config{
		Version:           mdutil.GetInt(md, "mux.version"),
		KeepAliveInterval: mdutil.GetDuration(md, "mux.keepaliveInterval"),
		KeepAliveDisabled: mdutil.GetBool(md, "mux.keepaliveDisabled"),
		KeepAliveTimeout:  mdutil.GetDuration(md, "mux.keepaliveTimeout"),
		MaxFrameSize:      mdutil.GetInt(md, "mux.maxFrameSize"),
		MaxReceiveBuffer:  mdutil.GetInt(md, "mux.maxReceiveBuffer"),
		MaxStreamBuffer:   mdutil.GetInt(md, "mux.maxStreamBuffer"),
	}

	d.md.handshakeTimeout = mdutil.GetDuration(md, "ws.handshakeTimeout", "handshakeTimeout")
	d.md.readHeaderTimeout = mdutil.GetDuration(md, "ws.readHeaderTimeout", "readHeaderTimeout")
	d.md.readBufferSize = mdutil.GetInt(md, "ws.readBufferSize", "readBufferSize")
	d.md.writeBufferSize = mdutil.GetInt(md, "ws.writeBufferSize", "writeBufferSize")
	d.md.enableCompression = mdutil.GetBool(md, "ws.enableCompression", "enableCompression")

	if m := mdutil.GetStringMapString(md, "ws.header", "header"); len(m) > 0 {
		h := http.Header{}
		for k, v := range m {
			h.Add(k, v)
		}
		d.md.header = h
	}

	if mdutil.GetBool(md, "ws.keepalive", "keepalive") {
		d.md.keepaliveInterval = mdutil.GetDuration(md, "ttl", "keepalive.interval")
		if d.md.keepaliveInterval <= 0 {
			d.md.keepaliveInterval = defaultKeepalivePeriod
		}
	}

	return
}
