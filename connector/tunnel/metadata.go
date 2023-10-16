package tunnel

import (
	"errors"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	"github.com/go-gost/relay"
	"github.com/google/uuid"
)

var (
	ErrInvalidTunnelID = errors.New("tunnel: invalid tunnel ID")
)

type metadata struct {
	connectTimeout time.Duration
	tunnelID       relay.TunnelID
	noDelay        bool
}

func (c *tunnelConnector) parseMetadata(md mdata.Metadata) (err error) {
	const (
		connectTimeout = "connectTimeout"
	)

	c.md.connectTimeout = mdutil.GetDuration(md, connectTimeout)
	c.md.noDelay = mdutil.GetBool(md, "nodelay")

	if s := mdutil.GetString(md, "tunnelID", "tunnel.id"); s != "" {
		uuid, err := uuid.Parse(s)
		if err != nil {
			return err
		}
		c.md.tunnelID = relay.NewTunnelID(uuid[:])
	}

	if c.md.tunnelID.IsZero() {
		return ErrInvalidTunnelID
	}
	return
}
