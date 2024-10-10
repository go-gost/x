package grpc

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

type metadata struct {
	insecure                     bool
	host                         string
	path                         string
	keepalive                    bool
	keepaliveTime                time.Duration
	keepaliveTimeout             time.Duration
	keepalivePermitWithoutStream bool
	minConnectTimeout            time.Duration
}

func (d *grpcDialer) parseMetadata(md mdata.Metadata) (err error) {
	d.md.insecure = mdutil.GetBool(md, "grpc.insecure", "grpcInsecure", "insecure")
	d.md.host = mdutil.GetString(md, "grpc.authority", "grpc.host", "host")
	d.md.path = mdutil.GetString(md, "grpc.path", "path")
	d.md.keepalive = mdutil.GetBool(md, "grpc.keepalive", "keepalive", "keepAlive")
	if d.md.keepalive {
		d.md.keepaliveTime = mdutil.GetDuration(md, "grpc.keepalive.time", "keepalive.time")
		if d.md.keepaliveTime <= 0 {
			d.md.keepaliveTime = 30 * time.Second
		}
		d.md.keepaliveTimeout = mdutil.GetDuration(md, "grpc.keepalive.timeout", "keepalive.timeout")
		if d.md.keepaliveTimeout <= 0 {
			d.md.keepaliveTimeout = 30 * time.Second
		}
		d.md.keepalivePermitWithoutStream = mdutil.GetBool(md, "grpc.keepalive.permitWithoutStream", "keepalive.permitWithoutStream")
	}
	d.md.minConnectTimeout = mdutil.GetDuration(md, "grpc.minConnectTimeout", "minConnectTimeout")
	if d.md.minConnectTimeout <= 0 {
		d.md.minConnectTimeout = 30 * time.Second
	}

	return
}
