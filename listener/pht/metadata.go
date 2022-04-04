package pht

import (
	"strings"

	mdata "github.com/go-gost/core/metadata"
	mdx "github.com/go-gost/x/metadata"
)

const (
	defaultAuthorizePath = "/authorize"
	defaultPushPath      = "/push"
	defaultPullPath      = "/pull"
	defaultBacklog       = 128
)

type metadata struct {
	authorizePath string
	pushPath      string
	pullPath      string
	backlog       int
}

func (l *phtListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		authorizePath = "authorizePath"
		pushPath      = "pushPath"
		pullPath      = "pullPath"

		backlog = "backlog"
	)

	l.md.authorizePath = mdx.GetString(md, authorizePath)
	if !strings.HasPrefix(l.md.authorizePath, "/") {
		l.md.authorizePath = defaultAuthorizePath
	}
	l.md.pushPath = mdx.GetString(md, pushPath)
	if !strings.HasPrefix(l.md.pushPath, "/") {
		l.md.pushPath = defaultPushPath
	}
	l.md.pullPath = mdx.GetString(md, pullPath)
	if !strings.HasPrefix(l.md.pullPath, "/") {
		l.md.pullPath = defaultPullPath
	}

	l.md.backlog = mdx.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	return
}
