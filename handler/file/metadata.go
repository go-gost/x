package file

import (
	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	dir string
	put bool
}

func (h *fileHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.dir = mdutil.GetString(md, "file.dir", "dir")
	h.md.put = mdutil.GetBool(md, "file.put", "put")
	return
}
