package pht

import (
	"strings"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
)

const (
	dialTimeout          = "dialTimeout"
	defaultAuthorizePath = "/authorize"
	defaultPushPath      = "/push"
	defaultPullPath      = "/pull"
)

const (
	defaultDialTimeout = 5 * time.Second
)

type metadata struct {
	dialTimeout   time.Duration
	authorizePath string
	pushPath      string
	pullPath      string
	host          string
}

func (d *phtDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		authorizePath = "authorizePath"
		pushPath      = "pushPath"
		pullPath      = "pullPath"
		host          = "host"
	)

	d.md.authorizePath = mdutil.GetString(md, authorizePath)
	if !strings.HasPrefix(d.md.authorizePath, "/") {
		d.md.authorizePath = defaultAuthorizePath
	}
	d.md.pushPath = mdutil.GetString(md, pushPath)
	if !strings.HasPrefix(d.md.pushPath, "/") {
		d.md.pushPath = defaultPushPath
	}
	d.md.pullPath = mdutil.GetString(md, pullPath)
	if !strings.HasPrefix(d.md.pullPath, "/") {
		d.md.pullPath = defaultPullPath
	}

	d.md.host = mdutil.GetString(md, host)
	return
}
