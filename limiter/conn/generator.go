package conn

import (
	limiter "github.com/go-gost/core/limiter/conn"
	"github.com/go-gost/x/limiter/stats"
)

// ConnLimitGenerator creates individual Limiter instances for use in
// per-IP or per-CIDR connection limiting.
type ConnLimitGenerator interface {
	Limiter() limiter.Limiter
}

type connLimitGenerator struct {
	n     int
	stats *stats.Stats
}

// NewConnLimitGenerator returns a ConnLimitGenerator that creates a new
// Limiter on each call to Limiter(), using the given limit n.
func NewConnLimitGenerator(n int) ConnLimitGenerator {
	return newConnLimitGenerator(n, nil)
}

func newConnLimitGenerator(n int, st *stats.Stats) ConnLimitGenerator {
	return &connLimitGenerator{
		n:     n,
		stats: st,
	}
}

func (p *connLimitGenerator) Limiter() limiter.Limiter {
	if p == nil || p.n <= 0 {
		return nil
	}
	return newLimiter(p.n, p.stats)
}

type connLimitSingleGenerator struct {
	limiter limiter.Limiter
}

// NewConnLimitSingleGenerator returns a ConnLimitGenerator that always
// returns the same Limiter instance, using the given limit n.
func NewConnLimitSingleGenerator(n int) ConnLimitGenerator {
	return newConnLimitSingleGenerator(n, nil)
}

func newConnLimitSingleGenerator(n int, st *stats.Stats) ConnLimitGenerator {
	p := &connLimitSingleGenerator{}
	if n > 0 {
		p.limiter = newLimiter(n, st)
	}
	return p
}

func (p *connLimitSingleGenerator) Limiter() limiter.Limiter {
	if p == nil {
		return nil
	}
	return p.limiter
}
