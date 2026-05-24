package conn

import (
	limiter "github.com/go-gost/core/limiter/conn"
)

// ConnLimitGenerator creates individual Limiter instances for use in
// per-IP or per-CIDR connection limiting.
type ConnLimitGenerator interface {
	Limiter() limiter.Limiter
}

type connLimitGenerator struct {
	n int
}

// NewConnLimitGenerator returns a ConnLimitGenerator that creates a new
// Limiter on each call to Limiter(), using the given limit n.
func NewConnLimitGenerator(n int) ConnLimitGenerator {
	return &connLimitGenerator{
		n: n,
	}
}

func (p *connLimitGenerator) Limiter() limiter.Limiter {
	if p == nil || p.n <= 0 {
		return nil
	}
	return NewLimiter(p.n)
}

type connLimitSingleGenerator struct {
	limiter limiter.Limiter
}

// NewConnLimitSingleGenerator returns a ConnLimitGenerator that always
// returns the same Limiter instance, using the given limit n.
func NewConnLimitSingleGenerator(n int) ConnLimitGenerator {
	p := &connLimitSingleGenerator{}
	if n > 0 {
		p.limiter = NewLimiter(n)
	}
	return p
}

func (p *connLimitSingleGenerator) Limiter() limiter.Limiter {
	if p == nil {
		return nil
	}
	return p.limiter
}
