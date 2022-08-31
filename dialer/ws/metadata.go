package ws

import (
	"net/http"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

const (
	defaultPath            = "/ws"
	defaultKeepAlivePeriod = 15 * time.Second
)

type metadata struct {
	host string
	path string

	handshakeTimeout  time.Duration
	readHeaderTimeout time.Duration
	readBufferSize    int
	writeBufferSize   int
	enableCompression bool

	header    http.Header
	keepAlive time.Duration
}

func (d *wsDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		host = "host"
		path = "path"

		handshakeTimeout  = "handshakeTimeout"
		readHeaderTimeout = "readHeaderTimeout"
		readBufferSize    = "readBufferSize"
		writeBufferSize   = "writeBufferSize"
		enableCompression = "enableCompression"

		header          = "header"
		keepAlive       = "keepAlive"
		keepAlivePeriod = "ttl"
	)

	d.md.host = mdx.GetString(md, host)

	d.md.path = mdx.GetString(md, path)
	if d.md.path == "" {
		d.md.path = defaultPath
	}

	d.md.handshakeTimeout = mdx.GetDuration(md, handshakeTimeout)
	d.md.readHeaderTimeout = mdx.GetDuration(md, readHeaderTimeout)
	d.md.readBufferSize = mdx.GetInt(md, readBufferSize)
	d.md.writeBufferSize = mdx.GetInt(md, writeBufferSize)
	d.md.enableCompression = mdx.GetBool(md, enableCompression)

	if m := mdx.GetStringMapString(md, header); len(m) > 0 {
		h := http.Header{}
		for k, v := range m {
			h.Add(k, v)
		}
		d.md.header = h
	}

	if mdx.GetBool(md, keepAlive) {
		d.md.keepAlive = mdx.GetDuration(md, keepAlivePeriod)
		if d.md.keepAlive <= 0 {
			d.md.keepAlive = defaultKeepAlivePeriod
		}
	}

	return
}
