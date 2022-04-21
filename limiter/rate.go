package limiter

import (
	"context"

	"github.com/go-gost/core/limiter"
	"golang.org/x/time/rate"
)

type llimiter struct {
	limiter *rate.Limiter
}

func Limiter(r int) limiter.Limiter {
	return &llimiter{
		limiter: rate.NewLimiter(rate.Limit(r), r),
	}
}

func (l *llimiter) Limit(b int) int {
	if l.limiter.Burst() < b {
		b = l.limiter.Burst()
	}
	l.limiter.WaitN(context.Background(), b)
	return b
}

type Generator interface {
	Generate() limiter.Limiter
}

type limiterGenerator struct {
	limit int
}

func NewGenerator(r int) Generator {
	return &limiterGenerator{limit: r}
}

// Generate creates a new Limiter.
func (g *limiterGenerator) Generate() limiter.Limiter {
	return Limiter(g.limit)
}

type multiLimiter struct {
	limiters []limiter.Limiter
}

func MultiLimiter(limiters ...limiter.Limiter) limiter.Limiter {
	return &multiLimiter{
		limiters: limiters,
	}
}

func (l *multiLimiter) Limit(b int) int {
	for i := range l.limiters {
		b = l.limiters[i].Limit(b)
	}
	return b
}

type rateLimiter struct {
	input  limiter.Limiter
	output limiter.Limiter
}

func RateLimiter(input, output limiter.Limiter) limiter.RateLimiter {
	if input == nil || output == nil {
		return nil
	}
	return &rateLimiter{
		input:  input,
		output: output,
	}
}

func (l *rateLimiter) Input() limiter.Limiter {
	return l.input
}

func (l *rateLimiter) Output() limiter.Limiter {
	return l.output
}
