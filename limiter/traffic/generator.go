package traffic

import (
	limiter "github.com/go-gost/core/limiter/traffic"
)

type limitGenerator struct {
	in    int
	out   int
	burst int
}

func newLimitGenerator(in, out, burst int) *limitGenerator {
	return &limitGenerator{
		in:    in,
		out:   out,
		burst: burst,
	}
}

func (p *limitGenerator) In() limiter.Limiter {
	if p == nil || p.in <= 0 {
		return nil
	}
	if p.burst > 0 {
		return NewLimiterWithBurst(p.in, p.burst)
	}
	return NewLimiter(p.in)
}

func (p *limitGenerator) Out() limiter.Limiter {
	if p == nil || p.out <= 0 {
		return nil
	}
	if p.burst > 0 {
		return NewLimiterWithBurst(p.out, p.burst)
	}
	return NewLimiter(p.out)
}
