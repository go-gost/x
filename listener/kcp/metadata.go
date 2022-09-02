package kcp

import (
	"encoding/json"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/core/metadata/util"
	kcp_util "github.com/go-gost/x/internal/util/kcp"
)

const (
	defaultBacklog = 128
)

type metadata struct {
	config  *kcp_util.Config
	backlog int
}

func (l *kcpListener) parseMetadata(md mdata.Metadata) (err error) {
	const (
		backlog    = "backlog"
		config     = "config"
		configFile = "c"
	)

	if file := mdutil.GetString(md, configFile); file != "" {
		l.md.config, err = kcp_util.ParseFromFile(file)
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
		l.md.config = cfg
	}

	if l.md.config == nil {
		l.md.config = kcp_util.DefaultConfig
	}

	l.md.backlog = mdutil.GetInt(md, backlog)
	if l.md.backlog <= 0 {
		l.md.backlog = defaultBacklog
	}

	return
}
