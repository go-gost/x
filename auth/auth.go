package auth

import (
	"bufio"
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/loader"
	xlogger "github.com/go-gost/x/logger"
)

type options struct {
	auths       map[string]string
	fileLoader  loader.Loader
	redisLoader loader.Loader
	httpLoader  loader.Loader
	period      time.Duration
	logger      logger.Logger
}

type Option func(opts *options)

func AuthsOption(auths map[string]string) Option {
	return func(opts *options) {
		opts.auths = auths
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

func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

// authenticator is an Authenticator that authenticates client by key-value pairs.
type authenticator struct {
	kvs        map[string]string
	mu         sync.RWMutex
	cancelFunc context.CancelFunc
	options    options
}

// NewAuthenticator creates an Authenticator that authenticates client by pre-defined user mapping.
func NewAuthenticator(opts ...Option) auth.Authenticator {
	var options options
	for _, opt := range opts {
		opt(&options)
	}
	if options.logger == nil {
		options.logger = xlogger.Nop()
	}

	ctx, cancel := context.WithCancel(context.TODO())
	p := &authenticator{
		kvs:        make(map[string]string),
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

// Authenticate checks the validity of the provided user-password pair.
func (p *authenticator) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	if p == nil {
		return "", true
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.kvs) == 0 {
		return "", false
	}

	v, ok := p.kvs[user]
	return user, ok && (v == "" || password == v)
}

func (p *authenticator) periodReload(ctx context.Context) error {
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
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *authenticator) reload(ctx context.Context) (err error) {
	kvs := make(map[string]string)
	for k, v := range p.options.auths {
		kvs[k] = v
	}

	m, err := p.load(ctx)
	for k, v := range m {
		kvs[k] = v
	}

	p.options.logger.Debugf("load items %d", len(m))

	p.mu.Lock()
	defer p.mu.Unlock()

	p.kvs = kvs

	return
}

func (p *authenticator) load(ctx context.Context) (m map[string]string, err error) {
	m = make(map[string]string)

	if p.options.fileLoader != nil {
		if mapper, ok := p.options.fileLoader.(loader.Mapper); ok {
			auths, er := mapper.Map(ctx)
			if er != nil {
				p.options.logger.Warnf("file loader: %v", er)
			}
			m = auths
		} else {
			r, er := p.options.fileLoader.Load(ctx)
			if er != nil {
				p.options.logger.Warnf("file loader: %v", er)
			}
			if auths, _ := p.parseAuths(r); auths != nil {
				m = auths
			}
		}
	}
	if p.options.redisLoader != nil {
		if mapper, ok := p.options.fileLoader.(loader.Mapper); ok {
			auths, er := mapper.Map(ctx)
			if er != nil {
				p.options.logger.Warnf("file loader: %v", er)
			}
			for k, v := range auths {
				m[k] = v
			}
		} else {
			r, er := p.options.redisLoader.Load(ctx)
			if er != nil {
				p.options.logger.Warnf("redis loader: %v", er)
			}
			if auths, _ := p.parseAuths(r); auths != nil {
				for k, v := range auths {
					m[k] = v
				}
			}
		}
	}
	if p.options.httpLoader != nil {
		r, er := p.options.httpLoader.Load(ctx)
		if er != nil {
			p.options.logger.Warnf("http loader: %v", er)
		}
		if auths, _ := p.parseAuths(r); auths != nil {
			for k, v := range auths {
				m[k] = v
			}
		}
	}

	return
}

func (p *authenticator) parseAuths(r io.Reader) (auths map[string]string, err error) {
	if r == nil {
		return
	}

	auths = make(map[string]string)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.Replace(scanner.Text(), "\t", " ", -1)
		line = strings.TrimSpace(line)
		if n := strings.IndexByte(line, '#'); n == 0 {
			continue
		}
		sp := strings.SplitN(line, " ", 2)
		if len(sp) == 1 {
			if k := strings.TrimSpace(sp[0]); k != "" {
				auths[k] = ""
			}
		}
		if len(sp) == 2 {
			if k := strings.TrimSpace(sp[0]); k != "" {
				auths[k] = strings.TrimSpace(sp[1])
			}
		}
	}

	err = scanner.Err()
	return
}

func (p *authenticator) Close() error {
	p.cancelFunc()
	if p.options.fileLoader != nil {
		p.options.fileLoader.Close()
	}
	if p.options.redisLoader != nil {
		p.options.redisLoader.Close()
	}
	return nil
}

type authenticatorGroup struct {
	authers []auth.Authenticator
}

func AuthenticatorGroup(authers ...auth.Authenticator) auth.Authenticator {
	return &authenticatorGroup{
		authers: authers,
	}
}

func (p *authenticatorGroup) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (string, bool) {
	if len(p.authers) == 0 {
		return "", false
	}
	for _, auther := range p.authers {
		if auther == nil {
			continue
		}

		if id, ok := auther.Authenticate(ctx, user, password, opts...); ok {
			return id, ok
		}
	}
	return "", false
}
