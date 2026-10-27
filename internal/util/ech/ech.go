// Package ech provides a DoH-based fetcher and cache for ECHConfigList
// (Encrypted Client Hello configuration) bytes.
package ech

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/go-gost/core/logger"
	xlogger "github.com/go-gost/x/logger"
	"github.com/go-gost/x/resolver/exchanger"
	"github.com/miekg/dns"
)

const (
	// defaultTTL is used when no explicit TTL is configured and the HTTPS RR
	// carries no usable TTL.
	defaultTTL = 300 * time.Second
	// minTTL is the lower bound applied to any positive cache TTL.
	minTTL = 30 * time.Second
	// negCacheTTL is how long a failed/empty lookup is cached.
	negCacheTTL = 30 * time.Second
)

// ErrNoECHConfig is returned when a DoH lookup succeeds but contains no ECH
// config for the requested name.
var ErrNoECHConfig = errors.New("ech: no ECH config")

// ErrDisabled is returned when the requested name has been disabled.
var ErrDisabled = errors.New("ech: disabled")

// Options holds configuration for a Client.
type Options struct {
	TTL       time.Duration
	Timeout   time.Duration
	Logger    logger.Logger
	TLSConfig *tls.Config
}

// Option allows setting Client options.
type Option func(*Options)

// TTLOption sets the cache TTL override.
func TTLOption(ttl time.Duration) Option {
	return func(opts *Options) {
		opts.TTL = ttl
	}
}

// TimeoutOption sets the DoH request timeout.
func TimeoutOption(timeout time.Duration) Option {
	return func(opts *Options) {
		opts.Timeout = timeout
	}
}

// LoggerOption sets the logger.
func LoggerOption(l logger.Logger) Option {
	return func(opts *Options) {
		opts.Logger = l
	}
}

// TLSConfigOption sets the TLS config used for DoH.
func TLSConfigOption(cfg *tls.Config) Option {
	return func(opts *Options) {
		opts.TLSConfig = cfg
	}
}

// entry is a cached lookup result.
type entry struct {
	list     []byte
	expires  time.Time
	negative bool
	err      error
}

// Client fetches and caches ECHConfigList bytes from a DoH endpoint.
type Client struct {
	doh       string
	exchanger exchanger.Exchanger

	ttl time.Duration
	log logger.Logger

	now func() time.Time

	mu       sync.RWMutex
	entries  map[string]*entry
	disabled map[string]time.Time
}

// NewClient creates a Client querying the given DoH URL.
func NewClient(doh string, opts ...Option) (*Client, error) {
	var options Options
	for _, opt := range opts {
		opt(&options)
	}

	u, err := url.Parse(doh)
	if err != nil {
		return nil, fmt.Errorf("ech: invalid doh url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("ech: doh url must use https: %s", doh)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("ech: doh url host is empty: %s", doh)
	}

	if options.Timeout <= 0 {
		options.Timeout = 5 * time.Second
	}
	if options.TLSConfig == nil {
		options.TLSConfig = &tls.Config{}
	}
	if options.Logger == nil {
		options.Logger = xlogger.Nop()
	}

	ex, err := exchanger.NewExchanger(doh, exchanger.TLSConfigOption(options.TLSConfig),
		exchanger.TimeoutOption(options.Timeout), exchanger.LoggerOption(options.Logger))
	if err != nil {
		return nil, fmt.Errorf("ech: failed to create exchanger: %w", err)
	}

	c := &Client{
		doh:       doh,
		exchanger: ex,
		ttl:       options.TTL,
		log:       options.Logger,
		now:       time.Now,
		entries:   make(map[string]*entry),
		disabled:  make(map[string]time.Time),
	}
	return c, nil
}

// ConfigList returns the cached (or freshly fetched) ECHConfigList for name.
func (c *Client) ConfigList(ctx context.Context, name string) ([]byte, error) {
	now := c.now()

	// Disabled check.
	c.mu.RLock()
	until, disabled := c.disabled[name]
	c.mu.RUnlock()
	if disabled && now.Before(until) {
		return nil, ErrDisabled
	}

	// Cache hit.
	c.mu.RLock()
	e, ok := c.entries[name]
	if ok && now.Before(e.expires) {
		list := cloneBytes(e.list)
		negative := e.negative
		cachedErr := e.err
		c.mu.RUnlock()
		if negative {
			if cachedErr != nil {
				return nil, cachedErr
			}
			return nil, ErrNoECHConfig
		}
		return list, nil
	}
	c.mu.RUnlock()

	// Miss: fetch.
	list, ttl, err := c.lookup(ctx, name)

	c.mu.Lock()
	defer c.mu.Unlock()
	now = c.now()

	if err != nil {
		c.entries[name] = &entry{expires: now.Add(negCacheTTL), negative: true, err: err}
		return nil, err
	}
	if len(list) == 0 {
		c.entries[name] = &entry{expires: now.Add(negCacheTTL), negative: true}
		return nil, ErrNoECHConfig
	}

	cacheTTL := ttl
	if c.ttl > 0 {
		cacheTTL = c.ttl
	}
	if cacheTTL <= 0 {
		cacheTTL = defaultTTL
	}
	if cacheTTL < minTTL {
		cacheTTL = minTTL
	}

	c.entries[name] = &entry{
		list:     cloneBytes(list),
		expires:  now.Add(cacheTTL),
		negative: false,
	}
	return cloneBytes(list), nil
}

// SetConfigList stores list in the cache, overriding the TTL.
func (c *Client) SetConfigList(name string, list []byte) {
	if len(list) == 0 {
		return
	}

	cacheTTL := c.ttl
	if cacheTTL <= 0 {
		cacheTTL = defaultTTL
	}
	if cacheTTL < minTTL {
		cacheTTL = minTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[name] = &entry{
		list:     cloneBytes(list),
		expires:  c.now().Add(cacheTTL),
		negative: false,
	}
	// Clear any disabled state for name.
	c.disabled[name] = time.Time{}
}

// Disable marks name as disabled until now+d.
func (c *Client) Disable(name string, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.disabled[name] = c.now().Add(d)
}

// lookup performs the DoH query and extracts the ECH config.
func (c *Client) lookup(ctx context.Context, name string) ([]byte, time.Duration, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeHTTPS)
	msg.SetEdns0(4096, false)

	buf, err := msg.Pack()
	if err != nil {
		return nil, 0, err
	}

	respBuf, err := c.exchanger.Exchange(ctx, buf)
	if err != nil {
		return nil, 0, err
	}

	var resp dns.Msg
	if err := resp.Unpack(respBuf); err != nil {
		return nil, 0, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, 0, fmt.Errorf("ech: dns rcode %d", resp.Rcode)
	}

	for _, rr := range resp.Answer {
		https, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}
		for _, kv := range https.Value {
			echKV, ok := kv.(*dns.SVCBECHConfig)
			if !ok {
				continue
			}
			if len(echKV.ECH) > 0 {
				ttl := time.Duration(https.Hdr.Ttl) * time.Second
				return cloneBytes(echKV.ECH), ttl, nil
			}
		}
	}
	return nil, 0, ErrNoECHConfig
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
