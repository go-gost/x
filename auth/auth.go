package auth

import (
	"bufio"
	"context"
	"io"
	"maps"
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
	logger     logger.Logger
}

// NewAuthenticator creates an Authenticator that authenticates client by pre-defined user mapping.
func NewAuthenticator(opts ...Option) auth.Authenticator {
	var options options
	for _, opt := range opts {
		opt(&options)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &authenticator{
		kvs:        make(map[string]string),
		cancelFunc: cancel,
		options:    options,
		logger:     options.logger,
	}
	if p.logger == nil {
		p.logger = xlogger.Nop()
	}

	go p.periodReload(ctx)

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
	if err := p.reload(ctx); err != nil {
		p.logger.Warnf("reload: %v", err)
	}

	period := p.options.period
	if period <= 0 {
		return nil
	}
	if period < time.Second {
		period = time.Second
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.reload(ctx); err != nil {
				p.logger.Warnf("reload: %v", err)
				// return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (p *authenticator) reload(ctx context.Context) error {
	kvs := make(map[string]string)
	maps.Copy(kvs, p.options.auths)

	m, err := p.load(ctx)
	if err != nil {
		return err
	}
	maps.Copy(kvs, m)

	p.logger.Debugf("load items %d", len(m))

	p.mu.Lock()
	defer p.mu.Unlock()

	p.kvs = kvs

	return nil
}

func (p *authenticator) load(ctx context.Context) (map[string]string, error) {
	m := make(map[string]string)
	var loadErr error

	if p.options.fileLoader != nil {
		if mapper, ok := p.options.fileLoader.(loader.Mapper); ok {
			auths, er := mapper.Map(ctx)
			if er != nil {
				p.logger.Warnf("file loader: %v", er)
				loadErr = er
			}
			m = auths
		} else {
			r, er := p.options.fileLoader.Load(ctx)
			if er != nil {
				p.logger.Warnf("file loader: %v", er)
				loadErr = er
			}
			if auths, err := p.parseAuths(r); err == nil {
				m = auths
			} else {
				p.logger.Warnf("file loader parse: %v", err)
			}
		}
	}
	if p.options.redisLoader != nil {
		if mapper, ok := p.options.redisLoader.(loader.Mapper); ok {
			auths, er := mapper.Map(ctx)
			if er != nil {
				p.logger.Warnf("redis loader: %v", er)
				if loadErr == nil {
					loadErr = er
				}
			}
			maps.Copy(m, auths)
		} else {
			r, er := p.options.redisLoader.Load(ctx)
			if er != nil {
				p.logger.Warnf("redis loader: %v", er)
				if loadErr == nil {
					loadErr = er
				}
			}
			if auths, err := p.parseAuths(r); err == nil {
				maps.Copy(m, auths)
			} else {
				p.logger.Warnf("redis loader parse: %v", err)
			}
		}
	}
	if p.options.httpLoader != nil {
		r, er := p.options.httpLoader.Load(ctx)
		if er != nil {
			p.logger.Warnf("http loader: %v", er)
			if loadErr == nil {
				loadErr = er
			}
		}
		if auths, err := p.parseAuths(r); err == nil {
			maps.Copy(m, auths)
		} else {
			p.logger.Warnf("http loader parse: %v", err)
		}
	}

	return m, loadErr
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
	if p.options.httpLoader != nil {
		p.options.httpLoader.Close()
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
