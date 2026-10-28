package ech

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"github.com/go-gost/core/logger"
	mdata "github.com/go-gost/core/metadata"
	xlogger "github.com/go-gost/x/logger"
	mdutil "github.com/go-gost/x/metadata/util"
)

// DisableTTL is how long ECH stays disabled for a name after a rejection
// without retry configs when fallback is enabled.
const DisableTTL = 5 * time.Minute

// Config holds the ECH settings of a dialer. It is parsed from the ech*
// metadata keys and owns the DoH client used to fetch ECHConfigList bytes.
type Config struct {
	Enabled     bool
	DoH         string
	Timeout     time.Duration
	TTL         time.Duration
	Fallback    bool
	DoHInsecure bool

	client *Client
	log    logger.Logger
}

// FromMetadata parses the ECH metadata keys.
//
// Supported keys: ech, ech.doh, ech.timeout, ech.ttl, ech.fallback and
// ech.dohInsecure.
func FromMetadata(md mdata.Metadata) Config {
	return Config{
		Enabled:     mdutil.GetBool(md, "ech"),
		DoH:         mdutil.GetString(md, "ech.doh"),
		Timeout:     mdutil.GetDuration(md, "ech.timeout"),
		TTL:         mdutil.GetDuration(md, "ech.ttl"),
		Fallback:    mdutil.GetBool(md, "ech.fallback"),
		DoHInsecure: mdutil.GetBool(md, "ech.dohInsecure"),
	}
}

// Init validates the configuration and creates the DoH client. base is the
// TLS config the dialer will handshake with; it is only inspected, never
// modified. Init is a no-op when ECH is disabled.
func (c *Config) Init(log logger.Logger, base *tls.Config) error {
	if !c.Enabled {
		return nil
	}
	if c.DoH == "" {
		return errors.New("ech: doh endpoint is required")
	}
	if base != nil {
		if base.MinVersion != 0 && base.MinVersion < tls.VersionTLS13 {
			return errors.New("ech: TLS 1.3 is required")
		}
		if base.MaxVersion != 0 && base.MaxVersion < tls.VersionTLS13 {
			return errors.New("ech: TLS 1.3 is required")
		}
	}
	if log == nil {
		log = xlogger.Nop()
	}

	dohTLS := &tls.Config{}
	if c.DoHInsecure {
		dohTLS = &tls.Config{InsecureSkipVerify: true}
	}

	client, err := NewClient(c.DoH,
		TTLOption(c.TTL),
		TimeoutOption(c.Timeout),
		TLSConfigOption(dohTLS),
		LoggerOption(log),
	)
	if err != nil {
		return err
	}
	c.client = client
	c.log = log
	return nil
}

// Active reports whether ECH is enabled and the DoH client is ready.
func (c *Config) Active() bool {
	return c != nil && c.client != nil
}

// Apply returns a clone of base with the ECHConfigList for serverName
// injected. When the lookup fails and Fallback is enabled it returns the plain
// clone so the caller proceeds with a regular handshake. When ECH is disabled
// base is returned unchanged.
func (c *Config) Apply(ctx context.Context, base *tls.Config, serverName string) (*tls.Config, error) {
	if !c.Active() {
		return base, nil
	}
	if serverName == "" {
		return nil, errors.New("ech: server name is required")
	}

	cfg := base
	if cfg == nil {
		cfg = &tls.Config{}
	}
	cfg = cfg.Clone()

	list, err := c.client.ConfigList(ctx, serverName)
	if err != nil {
		if c.Fallback {
			c.log.Warnf("ech: config list lookup failed: %v; falling back to plain TLS", err)
			return cfg, nil
		}
		return nil, err
	}

	cfg.EncryptedClientHelloConfigList = list
	if cfg.InsecureSkipVerify {
		cfg.EncryptedClientHelloRejectionVerify = func(tls.ConnectionState) error { return nil }
	}
	return cfg, nil
}

// OnRejection inspects err for a TLS ECH rejection. It returns a RetryableError
// when the handshake should be retried: either the server supplied new retry
// configs, or fallback is enabled and ECH has been disabled for serverName. It
// returns nil when err is not an ECH rejection, in which case the caller should
// propagate err unchanged.
func (c *Config) OnRejection(err error, serverName string) error {
	if !c.Active() || err == nil {
		return nil
	}

	var rej *tls.ECHRejectionError
	if !errors.As(err, &rej) {
		return nil
	}

	if len(rej.RetryConfigList) > 0 {
		c.client.SetConfigList(serverName, rej.RetryConfigList)
		return RetryableError{Err: err}
	}
	if c.Fallback {
		c.client.Disable(serverName, DisableTTL)
		return RetryableError{Err: err}
	}
	return nil
}

// OnDialError is the counterpart of OnRejection for dialers that complete the
// TLS handshake inside Dial. Such transports usually do not preserve the
// *tls.ECHRejectionError, so any dial failure with ECH active invalidates the
// cached config list and asks for a single retry with a fresh lookup.
func (c *Config) OnDialError(ctx context.Context, err error, serverName string) error {
	if !c.Active() || err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return nil
	}
	if rerr := c.OnRejection(err, serverName); rerr != nil {
		return rerr
	}
	c.client.Refresh(serverName)
	return RetryableError{Err: err}
}

// RetryableError wraps an error to signal that the enclosing chain hop may
// retry the connection once.
type RetryableError struct {
	Err error
}

func (e RetryableError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e RetryableError) Unwrap() error { return e.Err }

// RetryableHandshake implements the interface used by x/chain to retry a
// failed connection once on the same node.
func (e RetryableError) RetryableHandshake() bool { return true }
