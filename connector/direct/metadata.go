package direct

import (
	"strings"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	action string
}

func (c *directConnector) parseMetadata(md mdata.Metadata) (err error) {
	c.md.action = strings.ToLower(mdutil.GetString(md, "action"))
	return
}
