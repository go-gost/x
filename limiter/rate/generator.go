package rate

import (
	"github.com/go-gost/core/limiter/rate"
	limiter "github.com/go-gost/core/limiter/rate"
)

type RateLimitGenerator interface {
	Limiter() limiter.Limiter
}

type rateLimitGenerator struct {
	r float64
}

func NewRateLimitGenerator(r float64) RateLimitGenerator {
	return &rateLimitGenerator{
		r: r,
	}
}

func (p *rateLimitGenerator) Limiter() limiter.Limiter {
	if p == nil || p.r <= 0 {
		return nil
	}
	return NewLimiter(p.r, int(p.r)+1)
}

type rateLimitSingleGenerator struct {
	limiter rate.Limiter
}

func NewRateLimitSingleGenerator(r float64) RateLimitGenerator {
	p := &rateLimitSingleGenerator{}
	if r > 0 {
		p.limiter = NewLimiter(r, int(r)+1)
	}

	return p
}

func (p *rateLimitSingleGenerator) Limiter() limiter.Limiter {
	return p.limiter
}
