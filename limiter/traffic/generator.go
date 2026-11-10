package traffic

import (
	limiter "github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/x/limiter/stats"
)

type limitGenerator struct {
	in    int
	out   int
	burst int
	stats *stats.Stats
}

func newLimitGenerator(in, out, burst int, st *stats.Stats) *limitGenerator {
	return &limitGenerator{
		in:    in,
		out:   out,
		burst: burst,
		stats: st,
	}
}

func (p *limitGenerator) In() limiter.Limiter {
	if p == nil || p.in <= 0 {
		return nil
	}
	if p.burst > 0 {
		return newLimiterWithBurst(p.in, p.burst, p.stats)
	}
	return newLimiter(p.in, p.stats)
}

func (p *limitGenerator) Out() limiter.Limiter {
	if p == nil || p.out <= 0 {
		return nil
	}
	if p.burst > 0 {
		return newLimiterWithBurst(p.out, p.burst, p.stats)
	}
	return newLimiter(p.out, p.stats)
}
