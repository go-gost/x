package relay

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	"github.com/go-gost/relay"
	"github.com/go-gost/x/internal/util/mux"
	"github.com/google/uuid"
)

const (
	defaultMuxVersion = 2
)

type metadata struct {
	connectTimeout time.Duration
	noDelay        bool
	tunnelID       relay.TunnelID
	muxCfg         *mux.Config
}

func (c *relayConnector) parseMetadata(md mdata.Metadata) (err error) {
	const (
		connectTimeout = "connectTimeout"
		noDelay        = "nodelay"
	)

	c.md.connectTimeout = mdutil.GetDuration(md, connectTimeout)
	c.md.noDelay = mdutil.GetBool(md, noDelay)

	if s := mdutil.GetString(md, "tunnelID", "tunnel.id"); s != "" {
		uuid, err := uuid.Parse(s)
		if err != nil {
			return err
		}
		c.md.tunnelID = relay.NewTunnelID(uuid[:])
	}

	c.md.muxCfg = &mux.Config{
		Version:           mdutil.GetInt(md, "mux.version"),
		KeepAliveInterval: mdutil.GetDuration(md, "mux.keepaliveInterval"),
		KeepAliveDisabled: mdutil.GetBool(md, "mux.keepaliveDisabled"),
		KeepAliveTimeout:  mdutil.GetDuration(md, "mux.keepaliveTimeout"),
		MaxFrameSize:      mdutil.GetInt(md, "mux.maxFrameSize"),
		MaxReceiveBuffer:  mdutil.GetInt(md, "mux.maxReceiveBuffer"),
		MaxStreamBuffer:   mdutil.GetInt(md, "mux.maxStreamBuffer"),
	}
	if c.md.muxCfg.Version == 0 {
		c.md.muxCfg.Version = defaultMuxVersion
	}

	return
}
