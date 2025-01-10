package api

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	accesslog  bool
	pathPrefix string
}

func (h *apiHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.accesslog = mdutil.GetBool(md, "api.accessLog", "accessLog")
	h.md.pathPrefix = mdutil.GetString(md, "api.pathPrefix", "pathPrefix")
	return
}
