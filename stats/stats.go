package stats

import (
	"sync/atomic"

	"github.com/go-gost/core/observer"
)

type Kind int

const (
	KindTotalConns   Kind = 1
	KindCurrentConns Kind = 2
	KindInputBytes   Kind = 3
	KindOutputBytes  Kind = 4
	KindTotalErrs    Kind = 5
)

type Stats struct {
	updated      atomic.Bool
	totalConns   atomic.Uint64
	currentConns atomic.Int64
	inputBytes   atomic.Uint64
	outputBytes  atomic.Uint64
	totalErrs    atomic.Uint64
}

func (s *Stats) Add(kind Kind, n int64) {
	if s == nil {
		return
	}
	switch kind {
	case KindTotalConns:
		if n > 0 {
			s.totalConns.Add(uint64(n))
		}
	case KindCurrentConns:
		s.currentConns.Add(n)
	case KindInputBytes:
		if n > 0 {
			s.inputBytes.Add(uint64(n))
		}
	case KindOutputBytes:
		if n > 0 {
			s.outputBytes.Add(uint64(n))
		}
	case KindTotalErrs:
		if n > 0 {
			s.totalErrs.Add(uint64(n))
		}
	}
	s.updated.Store(true)
}

func (s *Stats) Get(kind Kind) uint64 {
	if s == nil {
		return 0
	}

	switch kind {
	case KindTotalConns:
		return s.totalConns.Load()
	case KindCurrentConns:
		return uint64(s.currentConns.Load())
	case KindInputBytes:
		return s.inputBytes.Load()
	case KindOutputBytes:
		return s.outputBytes.Load()
	case KindTotalErrs:
		return s.totalErrs.Load()
	}
	return 0
}

func (s *Stats) IsUpdated() bool {
	return s.updated.Swap(false)
}

type StatsEvent struct {
	Kind    string
	Service string
	Client  string

	TotalConns   uint64
	CurrentConns uint64
	InputBytes   uint64
	OutputBytes  uint64
	TotalErrs    uint64
}

func (StatsEvent) Type() observer.EventType {
	return observer.EventStats
}
