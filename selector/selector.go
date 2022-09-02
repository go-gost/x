package selector

import (
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/selector"
)

// default options for FailFilter
const (
	DefaultMaxFails    = 1
	DefaultFailTimeout = 10 * time.Second
)

const (
	labelWeight      = "weight"
	labelBackup      = "backup"
	labelMaxFails    = "maxFails"
	labelFailTimeout = "failTimeout"
)

var (
	DefaultNodeSelector = NewSelector(
		RoundRobinStrategy[*chain.Node](),
		// FailFilter[*Node](1, DefaultFailTimeout),
	)
	DefaultChainSelector = NewSelector(
		RoundRobinStrategy[chain.SelectableChainer](),
		// FailFilter[SelectableChainer](1, DefaultFailTimeout),
	)
)

type defaultSelector[T selector.Selectable] struct {
	strategy selector.Strategy[T]
	filters  []selector.Filter[T]
}

func NewSelector[T selector.Selectable](strategy selector.Strategy[T], filters ...selector.Filter[T]) selector.Selector[T] {
	return &defaultSelector[T]{
		filters:  filters,
		strategy: strategy,
	}
}

func (s *defaultSelector[T]) Select(vs ...T) (v T) {
	for _, filter := range s.filters {
		vs = filter.Filter(vs...)
	}
	if len(vs) == 0 {
		return
	}
	return s.strategy.Apply(vs...)
}
