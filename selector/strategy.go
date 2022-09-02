package selector

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/selector"
)

type roundRobinStrategy[T selector.Selectable] struct {
	counter uint64
}

// RoundRobinStrategy is a strategy for node selector.
// The node will be selected by round-robin algorithm.
func RoundRobinStrategy[T selector.Selectable]() selector.Strategy[T] {
	return &roundRobinStrategy[T]{}
}

func (s *roundRobinStrategy[T]) Apply(vs ...T) (v T) {
	if len(vs) == 0 {
		return
	}

	n := atomic.AddUint64(&s.counter, 1) - 1
	return vs[int(n%uint64(len(vs)))]
}

type randomStrategy[T selector.Selectable] struct {
	rand *rand.Rand
	mux  sync.Mutex
}

// RandomStrategy is a strategy for node selector.
// The node will be selected randomly.
func RandomStrategy[T selector.Selectable]() selector.Strategy[T] {
	return &randomStrategy[T]{
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (s *randomStrategy[T]) Apply(vs ...T) (v T) {
	if len(vs) == 0 {
		return
	}

	s.mux.Lock()
	defer s.mux.Unlock()

	r := s.rand.Int()

	return vs[r%len(vs)]
}

type fifoStrategy[T selector.Selectable] struct{}

// FIFOStrategy is a strategy for node selector.
// The node will be selected from first to last,
// and will stick to the selected node until it is failed.
func FIFOStrategy[T selector.Selectable]() selector.Strategy[T] {
	return &fifoStrategy[T]{}
}

// Apply applies the fifo strategy for the nodes.
func (s *fifoStrategy[T]) Apply(vs ...T) (v T) {
	if len(vs) == 0 {
		return
	}
	return vs[0]
}
