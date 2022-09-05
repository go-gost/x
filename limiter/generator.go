package limiter

import (
	"github.com/go-gost/core/limiter"
)

type RateLimitGenerator interface {
	In() limiter.Limiter
	Out() limiter.Limiter
}

type rateLimitGenerator struct {
	in  int
	out int
}

func NewRateLimitGenerator(in, out int) RateLimitGenerator {
	return &rateLimitGenerator{
		in:  in,
		out: out,
	}
}

func (p *rateLimitGenerator) In() limiter.Limiter {
	if p == nil || p.in <= 0 {
		return nil
	}
	return NewLimiter(p.in)
}

func (p *rateLimitGenerator) Out() limiter.Limiter {
	if p == nil || p.out <= 0 {
		return nil
	}
	return NewLimiter(p.out)
}

type rateLimitSingleGenerator struct {
	in  limiter.Limiter
	out limiter.Limiter
}

func NewRateLimitSingleGenerator(in, out int) RateLimitGenerator {
	p := &rateLimitSingleGenerator{}
	if in > 0 {
		p.in = NewLimiter(in)
	}
	if out > 0 {
		p.out = NewLimiter(out)
	}

	return p
}

func (p *rateLimitSingleGenerator) In() limiter.Limiter {
	return p.in
}

func (p *rateLimitSingleGenerator) Out() limiter.Limiter {
	return p.out
}
