package traffic

import (
	limiter "github.com/go-gost/core/limiter/traffic"
)

type TrafficLimitGenerator interface {
	In() limiter.Limiter
	Out() limiter.Limiter
}

type trafficLimitGenerator struct {
	in  int
	out int
}

func NewTrafficLimitGenerator(in, out int) TrafficLimitGenerator {
	return &trafficLimitGenerator{
		in:  in,
		out: out,
	}
}

func (p *trafficLimitGenerator) In() limiter.Limiter {
	if p == nil || p.in <= 0 {
		return nil
	}
	return NewLimiter(p.in)
}

func (p *trafficLimitGenerator) Out() limiter.Limiter {
	if p == nil || p.out <= 0 {
		return nil
	}
	return NewLimiter(p.out)
}

type trafficLimitSingleGenerator struct {
	in  limiter.Limiter
	out limiter.Limiter
}

func NewTrafficLimitSingleGenerator(in, out int) TrafficLimitGenerator {
	p := &trafficLimitSingleGenerator{}
	if in > 0 {
		p.in = NewLimiter(in)
	}
	if out > 0 {
		p.out = NewLimiter(out)
	}

	return p
}

func (p *trafficLimitSingleGenerator) In() limiter.Limiter {
	return p.in
}

func (p *trafficLimitSingleGenerator) Out() limiter.Limiter {
	return p.out
}
