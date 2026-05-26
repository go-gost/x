package api

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

// metadata holds parsed configuration for the api handler.
type metadata struct {
	accesslog  bool
	pathPrefix string
}

// parseMetadata extracts api-specific configuration from the generic metadata map.
func (h *apiHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.accesslog = mdutil.GetBool(md, "api.accessLog", "accessLog")
	h.md.pathPrefix = mdutil.GetString(md, "api.pathPrefix", "pathPrefix")
	return
}
