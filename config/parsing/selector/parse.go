package selector

import (
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/selector"
	"github.com/go-gost/x/config"
	xs "github.com/go-gost/x/selector"
)

func ParseChainSelector(cfg *config.SelectorConfig) selector.Selector[chain.Chainer] {
	if cfg == nil {
		return nil
	}

	var strategy selector.Strategy[chain.Chainer]
	switch cfg.Strategy {
	case "round", "rr":
		strategy = xs.RoundRobinStrategy[chain.Chainer]()
	case "random", "rand":
		strategy = xs.RandomStrategy[chain.Chainer]()
	case "fifo", "ha":
		strategy = xs.FIFOStrategy[chain.Chainer]()
	case "hash":
		strategy = xs.HashStrategy[chain.Chainer]()
	default:
		strategy = xs.RoundRobinStrategy[chain.Chainer]()
	}
	return xs.NewSelector(
		strategy,
		xs.FailFilter[chain.Chainer](cfg.MaxFails, cfg.FailTimeout),
		xs.BackupFilter[chain.Chainer](),
	)
}

func ParseNodeSelector(cfg *config.SelectorConfig) selector.Selector[*chain.Node] {
	if cfg == nil {
		return nil
	}

	var strategy selector.Strategy[*chain.Node]
	switch cfg.Strategy {
	case "round", "rr":
		strategy = xs.RoundRobinStrategy[*chain.Node]()
	case "random", "rand":
		strategy = xs.RandomStrategy[*chain.Node]()
	case "fifo", "ha":
		strategy = xs.FIFOStrategy[*chain.Node]()
	case "hash":
		strategy = xs.HashStrategy[*chain.Node]()
	default:
		strategy = xs.RoundRobinStrategy[*chain.Node]()
	}

	return xs.NewSelector(
		strategy,
		xs.FailFilter[*chain.Node](cfg.MaxFails, cfg.FailTimeout),
		xs.BackupFilter[*chain.Node](),
	)
}

func DefaultNodeSelector() selector.Selector[*chain.Node] {
	return xs.NewSelector(
		xs.RoundRobinStrategy[*chain.Node](),
		xs.FailFilter[*chain.Node](xs.DefaultMaxFails, xs.DefaultFailTimeout),
		xs.BackupFilter[*chain.Node](),
	)
}

func DefaultChainSelector() selector.Selector[chain.Chainer] {
	return xs.NewSelector(
		xs.RoundRobinStrategy[chain.Chainer](),
		xs.FailFilter[chain.Chainer](xs.DefaultMaxFails, xs.DefaultFailTimeout),
		xs.BackupFilter[chain.Chainer](),
	)
}
