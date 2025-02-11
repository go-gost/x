package tunnel

import (
	"errors"
	"time"

	mdata "github.com/go-gost/core/metadata"
	"github.com/go-gost/relay"
	mdutil "github.com/go-gost/x/metadata/util"
	"github.com/google/uuid"
)

var (
	ErrInvalidRouterID = errors.New("router: invalid router ID")
)

type metadata struct {
	connectTimeout time.Duration
	routerID       relay.TunnelID
}

func (c *routerConnector) parseMetadata(md mdata.Metadata) (err error) {
	c.md.connectTimeout = mdutil.GetDuration(md, "connectTimeout")

	if s := mdutil.GetString(md, "router.id"); s != "" {
		uuid, err := uuid.Parse(s)
		if err != nil {
			return err
		}
		c.md.routerID = relay.NewTunnelID(uuid[:])
	}

	return
}
