package ingress

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	ingress_pkg "github.com/go-gost/core/ingress"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/loader"
	"google.golang.org/grpc"
)

type Rule struct {
	Hostname string
	Endpoint string
}

type options struct {
	rules       []Rule
	fileLoader  loader.Loader
	redisLoader loader.Loader
	httpLoader  loader.Loader
	client      *grpc.ClientConn
	period      time.Duration
	logger      logger.Logger
}

type Option func(opts *options)

func RulesOption(rules []Rule) Option {
	return func(opts *options) {
		opts.rules = rules
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

func HTTPLoaderOption(httpLoader loader.Loader) Option {
	return func(opts *options) {
		opts.httpLoader = httpLoader
	}
}

func PluginConnOption(c *grpc.ClientConn) Option {
	return func(opts *options) {
		opts.client = c
	}
}

func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

type ingress struct {
	rules      map[string]Rule
	cancelFunc context.CancelFunc
	options    options
	mu         sync.RWMutex
}

// NewIngress creates and initializes a new Ingress.
func NewIngress(opts ...Option) ingress_pkg.Ingress {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	ctx, cancel := context.WithCancel(context.TODO())

	ing := &ingress{
		cancelFunc: cancel,
		options:    options,
	}

	if err := ing.reload(ctx); err != nil {
		options.logger.Warnf("reload: %v", err)
	}
	if ing.options.period > 0 {
		go ing.periodReload(ctx)
	}

	return ing
}

func (ing *ingress) periodReload(ctx context.Context) error {
	period := ing.options.period
	if period < time.Second {
		period = time.Second
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := ing.reload(ctx); err != nil {
				ing.options.logger.Warnf("reload: %v", err)
				// return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (ing *ingress) reload(ctx context.Context) error {
	rules := make(map[string]Rule)

	fn := func(rule Rule) {
		if rule.Hostname == "" || rule.Endpoint == "" {
			return
		}
		host := rule.Hostname
		if host[0] == '*' {
			host = host[1:]
		}
		rules[host] = rule
	}

	for _, rule := range ing.options.rules {
		fn(rule)
	}

	v, err := ing.load(ctx)
	if err != nil {
		return err
	}
	for _, rule := range v {
		fn(rule)
	}

	ing.mu.Lock()
	defer ing.mu.Unlock()

	ing.rules = rules

	return nil
}

func (ing *ingress) load(ctx context.Context) (rules []Rule, err error) {
	if ing.options.fileLoader != nil {
		if lister, ok := ing.options.fileLoader.(loader.Lister); ok {
			list, er := lister.List(ctx)
			if er != nil {
				ing.options.logger.Warnf("file loader: %v", er)
			}
			for _, s := range list {
				rules = append(rules, ing.parseLine(s))
			}
		} else {
			r, er := ing.options.fileLoader.Load(ctx)
			if er != nil {
				ing.options.logger.Warnf("file loader: %v", er)
			}
			if v, _ := ing.parseRules(r); v != nil {
				rules = append(rules, v...)
			}
		}
	}
	if ing.options.redisLoader != nil {
		if lister, ok := ing.options.redisLoader.(loader.Lister); ok {
			list, er := lister.List(ctx)
			if er != nil {
				ing.options.logger.Warnf("redis loader: %v", er)
			}
			for _, v := range list {
				rules = append(rules, ing.parseLine(v))
			}
		} else {
			r, er := ing.options.redisLoader.Load(ctx)
			if er != nil {
				ing.options.logger.Warnf("redis loader: %v", er)
			}
			v, _ := ing.parseRules(r)
			rules = append(rules, v...)
		}
	}
	if ing.options.httpLoader != nil {
		r, er := ing.options.httpLoader.Load(ctx)
		if er != nil {
			ing.options.logger.Warnf("http loader: %v", er)
		}
		v, _ := ing.parseRules(r)
		rules = append(rules, v...)
	}

	ing.options.logger.Debugf("load items %d", len(rules))
	return
}

func (ing *ingress) parseRules(r io.Reader) (rules []Rule, err error) {
	if r == nil {
		return
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if rule := ing.parseLine(scanner.Text()); rule.Hostname != "" {
			rules = append(rules, rule)
		}
	}

	err = scanner.Err()
	return
}

func (ing *ingress) Get(ctx context.Context, host string) string {
	if host == "" || ing == nil {
		return ""
	}

	// try to strip the port
	if v, _, _ := net.SplitHostPort(host); v != "" {
		host = v
	}

	if ing == nil || len(ing.rules) == 0 {
		return ""
	}

	ing.options.logger.Debugf("ingress: lookup %s", host)
	ep := ing.lookup(host)
	if ep == "" {
		ep = ing.lookup("." + host)
	}
	if ep == "" {
		s := host
		for {
			if index := strings.IndexByte(s, '.'); index > 0 {
				ep = ing.lookup(s[index:])
				s = s[index+1:]
				if ep == "" {
					continue
				}
			}
			break
		}
	}

	if ep != "" {
		ing.options.logger.Debugf("ingress: %s -> %s", host, ep)
	}

	return ep
}

func (ing *ingress) lookup(host string) string {
	if ing == nil || len(ing.rules) == 0 {
		return ""
	}

	ing.mu.RLock()
	defer ing.mu.RUnlock()

	return ing.rules[host].Endpoint
}

func (ing *ingress) parseLine(s string) (rule Rule) {
	line := strings.Replace(s, "\t", " ", -1)
	line = strings.TrimSpace(line)
	if n := strings.IndexByte(line, '#'); n >= 0 {
		line = line[:n]
	}
	var sp []string
	for _, s := range strings.Split(line, " ") {
		if s = strings.TrimSpace(s); s != "" {
			sp = append(sp, s)
		}
	}
	if len(sp) < 2 {
		return // invalid lines are ignored
	}

	return Rule{
		Hostname: sp[0],
		Endpoint: sp[1],
	}
}

func (ing *ingress) Close() error {
	ing.cancelFunc()
	if ing.options.fileLoader != nil {
		ing.options.fileLoader.Close()
	}
	if ing.options.redisLoader != nil {
		ing.options.redisLoader.Close()
	}
	return nil
}
