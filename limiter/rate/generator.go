package rate

import (
	limiter "github.com/go-gost/core/limiter/rate"
)

// RateLimitGenerator is an interface for generating [limiter.Limiter] instances.
type RateLimitGenerator interface {
	Limiter() limiter.Limiter
}

type rateLimitGenerator struct {
	r float64
}

// NewRateLimitGenerator creates a [RateLimitGenerator] that produces a new [limiter.Limiter]
// for each call to Limiter(). Useful for per-IP rate limiting where each IP should
// have its own independent rate limiter.
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
	limiter limiter.Limiter
}

// NewRateLimitSingleGenerator creates a [RateLimitGenerator] that returns the same
// [limiter.Limiter] for every call to Limiter(). Useful for shared global rate limits
// where all callers share the same token bucket.
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
