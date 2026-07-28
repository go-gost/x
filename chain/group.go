package chain

import (
	"context"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/routing"
	"github.com/go-gost/core/selector"
)

// ChainEntry wraps a chain.Chainer with an optional matcher and an independent
// failure marker for chain-level probe tracking. The entry's marker is
// separate from any node-level markers inside the chain so that probe
// Reset() cannot undo a node-level failCodes Mark().
type ChainEntry struct {
	chainer chain.Chainer
	matcher routing.Matcher
	probe   *chain.ProbeConfig
	marker  selector.Marker
}

// NewChainEntry creates a ChainEntry. matcher may be nil (unconditional
// catch-all). probe may be nil (no health check for this entry).
func NewChainEntry(c chain.Chainer, m routing.Matcher, probe *chain.ProbeConfig) *ChainEntry {
	return &ChainEntry{
		chainer: c,
		matcher: m,
		probe:   probe,
		marker:  selector.NewFailMarker(),
	}
}

// Route implements chain.Chainer so the entry can be passed directly to the
// group selector. The selector's FailFilter reads Marker() from the entry,
// not from the underlying chain — this keeps probe-driven marking independent
// of any node-level markers.
func (e *ChainEntry) Route(ctx context.Context, network, address string, opts ...chain.RouteOption) chain.Route {
	return e.chainer.Route(ctx, network, address, opts...)
}

// Marker implements selector.Markable.
func (e *ChainEntry) Marker() selector.Marker {
	return e.marker
}
