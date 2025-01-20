package pht

import (
	"strings"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
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
	mptcp         bool
}

func (l *phtListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		authorizePath = "authorizePath"
		pushPath      = "pushPath"
		pullPath      = "pullPath"

		backlog = "backlog"
	)

	l.md.authorizePath = mdutil.GetString(md, authorizePath)
	if !strings.HasPrefix(l.md.authorizePath, "/") {
		l.md.authorizePath = defaultAuthorizePath
	}
	l.md.pushPath = mdutil.GetString(md, pushPath)
	if !strings.HasPrefix(l.md.pushPath, "/") {
		l.md.pushPath = defaultPushPath
	}
	l.md.pullPath = mdutil.GetString(md, pullPath)
	if !strings.HasPrefix(l.md.pullPath, "/") {
		l.md.pullPath = defaultPullPath
	}

	l.md.backlog = mdutil.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	l.md.mptcp = mdutil.GetBool(md, "mptcp")

	return
}
