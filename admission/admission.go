package admission

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	admission_pkg "github.com/go-gost/core/admission"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/loader"
	"github.com/go-gost/x/internal/matcher"
)

type options struct {
	reverse     bool
	matchers    []string
	fileLoader  loader.Loader
	redisLoader loader.Loader
	period      time.Duration
	logger      logger.Logger
}

type Option func(opts *options)

func ReverseOption(reverse bool) Option {
	return func(opts *options) {
		opts.reverse = reverse
	}
}

func MatchersOption(matchers []string) Option {
	return func(opts *options) {
		opts.matchers = matchers
	}
}

func ReloadPeriodOption(period time.Duration) Option {
	return func(opts *options) {
		opts.period = period
	}
}

func FileLoaderOption(fileLoader loader.Loader) Option {
	return func(opts *options) {
		opts.fileLoader = fileLoader
	}
}

func RedisLoaderOption(redisLoader loader.Loader) Option {
	return func(opts *options) {
		opts.redisLoader = redisLoader
	}
}

func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

type admission struct {
	ipMatcher   matcher.Matcher
	cidrMatcher matcher.Matcher
	mu          sync.RWMutex
	cancelFunc  context.CancelFunc
	options     options
}

// NewAdmission creates and initializes a new Admission using matcher patterns as its match rules.
// The rules will be reversed if the reverse is true.
func NewAdmission(opts ...Option) admission_pkg.Admission {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	ctx, cancel := context.WithCancel(context.TODO())
	p := &admission{
		cancelFunc: cancel,
		options:    options,
	}

	if err := p.reload(ctx); err != nil {
		options.logger.Warnf("reload: %v", err)
	}
	if p.options.period > 0 {
		go p.periodReload(ctx)
	}

	return p
}

func (p *admission) Admit(addr string) bool {
	if addr == "" || p == nil {
		return false
	}

	// try to strip the port
	if host, _, _ := net.SplitHostPort(addr); host != "" {
		addr = host
	}

	matched := p.matched(addr)

	b := !p.options.reverse && matched ||
		p.options.reverse && !matched
	return b
}

func (p *admission) periodReload(ctx context.Context) error {
	period := p.options.period
	if period < time.Second {
		period = time.Second
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.reload(ctx); err != nil {
				p.options.logger.Warnf("reload: %v", err)
				// return err
			}
			p.options.logger.Debugf("admission reload done")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *admission) reload(ctx context.Context) error {
	v, err := p.load(ctx)
	if err != nil {
		return err
	}
	patterns := append(p.options.matchers, v...)

	var ips []net.IP
	var inets []*net.IPNet
	for _, pattern := range patterns {
		if ip := net.ParseIP(pattern); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if _, inet, err := net.ParseCIDR(pattern); err == nil {
			inets = append(inets, inet)
			continue
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.ipMatcher = matcher.IPMatcher(ips)
	p.cidrMatcher = matcher.CIDRMatcher(inets)

	return nil
}

func (p *admission) load(ctx context.Context) (patterns []string, err error) {
	if p.options.fileLoader != nil {
		r, er := p.options.fileLoader.Load(ctx)
		if er != nil {
			p.options.logger.Warnf("file loader: %v", er)
		}
		if v, _ := p.parsePatterns(r); v != nil {
			patterns = append(patterns, v...)
		}
	}
	if p.options.redisLoader != nil {
		r, er := p.options.redisLoader.Load(ctx)
		if er != nil {
			p.options.logger.Warnf("redis loader: %v", er)
		}
		if v, _ := p.parsePatterns(r); v != nil {
			patterns = append(patterns, v...)
		}
	}

	return
}

func (p *admission) parsePatterns(r io.Reader) (patterns []string, err error) {
	if r == nil {
		return
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if n := strings.IndexByte(line, '#'); n >= 0 {
			line = line[:n]
		}
		line = strings.TrimSpace(line)
		if line != "" {
			patterns = append(patterns, line)
		}
	}

	err = scanner.Err()
	return
}

func (p *admission) matched(addr string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.ipMatcher.Match(addr) ||
		p.cidrMatcher.Match(addr)
}

func (p *admission) Close() error {
	p.cancelFunc()
	if p.options.fileLoader != nil {
		p.options.fileLoader.Close()
	}
	if p.options.redisLoader != nil {
		p.options.redisLoader.Close()
	}
	return nil
}
