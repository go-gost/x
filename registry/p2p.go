package registry

import (
	reg "github.com/go-gost/core/registry"
	xp2p "github.com/go-gost/x/p2p"
)

// p2pRegistry stores p2p.TunnelProvider instances. It uses the base registry
// methods without a wrapper: providers are captured once at node-parse time
// and have no periodic reload source (unlike recorders, whose hot-reload
// registry resolves by name on every call).
type p2pRegistry struct {
	registry[xp2p.TunnelProvider]
}

// P2PRegistry returns the global registry of p2p tunnel providers.
func P2PRegistry() reg.Registry[xp2p.TunnelProvider] {
	return p2pReg
}