package tun

import (
	"math"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultKeepAlivePeriod = 10 * time.Second
	MaxMessageSize         = math.MaxUint16
)

type metadata struct {
	keepAlivePeriod time.Duration
	passphrase      string
	relayTarget     string
	p2p             bool
}

func (h *tunHandler) parseMetadata(md mdata.Metadata) (err error) {
	if dec, ok := md.Get("decisionEvaluator").(DecisionEvaluator); ok {
		h.dec = dec
	}

	if mdutil.GetBool(md, "tun.keepalive", "keepalive") {
		h.md.keepAlivePeriod = mdutil.GetDuration(md, "tun.ttl", "ttl")
		if h.md.keepAlivePeriod <= 0 {
			h.md.keepAlivePeriod = defaultKeepAlivePeriod
		}
	}

	h.md.passphrase = mdutil.GetString(md, "tun.token", "token", "passphrase")
	// relayTarget is used for TCP/WSS overlays where the server expects a relay CONNECT
	// request with a non-empty destination address.
	h.md.relayTarget = mdutil.GetString(md, "tun.relayTarget", "relayTarget", "relay_target")
	h.md.p2p = mdutil.GetBool(md, "tun.p2p", "p2p")
	return
}
