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
}

func (c *tunnelConnector) parseMetadata(md mdata.Metadata) (err error) {
	const (
		connectTimeout = "connectTimeout"
		noDelay        = "nodelay"
	)

	c.md.connectTimeout = mdutil.GetDuration(md, connectTimeout)

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
