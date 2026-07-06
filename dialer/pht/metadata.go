package pht

import (
	"net/http"
	"strings"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultPushPath = "/push"
	defaultPullPath = "/pull"
)

type metadata struct {
	pushPath string
	pullPath string
	host     string
	header   http.Header
}

func (d *phtDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		pushPath = "pushPath"
		pullPath = "pullPath"
		host     = "host"
		header   = "header"
	)

	d.md.pushPath = mdutil.GetString(md, pushPath)
	if !strings.HasPrefix(d.md.pushPath, "/") {
		d.md.pushPath = defaultPushPath
	}
	d.md.pullPath = mdutil.GetString(md, pullPath)
	if !strings.HasPrefix(d.md.pullPath, "/") {
		d.md.pullPath = defaultPullPath
	}

	d.md.host = mdutil.GetString(md, host)

	// Parse custom headers
	if m := mdutil.GetStringMapString(md, header); len(m) > 0 {
		h := http.Header{}
		for k, v := range m {
			h.Add(k, v)
		}
		d.md.header = h
	}

	return
}
