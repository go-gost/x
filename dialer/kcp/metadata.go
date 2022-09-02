package kcp

import (
	"encoding/json"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	kcp_util "github.com/go-gost/x/internal/util/kcp"
)

type metadata struct {
	handshakeTimeout time.Duration
	config           *kcp_util.Config
}

func (d *kcpDialer) parseMetadata(md mdata.Metadata) (err error) {
	const (
		config           = "config"
		configFile       = "c"
		handshakeTimeout = "handshakeTimeout"
	)

	if file := mdutil.GetString(md, configFile); file != "" {
		d.md.config, err = kcp_util.ParseFromFile(file)
		if err != nil {
			return
		}
	}

	if m := mdutil.GetStringMap(md, config); len(m) > 0 {
		b, err := json.Marshal(m)
		if err != nil {
			return err
		}
		cfg := &kcp_util.Config{}
		if err := json.Unmarshal(b, cfg); err != nil {
			return err
		}
		d.md.config = cfg
	}
	if d.md.config == nil {
		d.md.config = kcp_util.DefaultConfig
	}

	d.md.handshakeTimeout = mdutil.GetDuration(md, handshakeTimeout)
	return
}
