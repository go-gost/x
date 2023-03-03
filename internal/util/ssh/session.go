package ssh

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/core/logger"
	"golang.org/x/crypto/ssh"
)

const (
	defaultKeepaliveInterval = 30 * time.Second
	defaultKeepaliveTimeout  = 15 * time.Second
	defaultkeepaliveRetries  = 1
)

type Session struct {
	net.Conn
	client *ssh.Client
	closed chan struct{}
	dead   chan struct{}
	log    logger.Logger
}

func NewSession(c net.Conn, client *ssh.Client, log logger.Logger) *Session {
	return &Session{
		Conn:   c,
		client: client,
		closed: make(chan struct{}),
		dead:   make(chan struct{}),
		log:    log,
	}
}

func (s *Session) OpenChannel(name string) (ssh.Channel, <-chan *ssh.Request, error) {
	return s.client.OpenChannel(name, nil)
}

func (s *Session) IsClosed() bool {
	select {
	case <-s.dead:
		return true
	case <-s.closed:
		return true
	default:
	}
	return false
}

func (s *Session) Wait() error {
	defer close(s.closed)

	return s.client.Wait()
}

func (s *Session) WaitClose() {
	defer s.client.Close()

	select {
	case <-s.dead:
		s.log.Debugf("session is dead")
	case <-s.closed:
		s.log.Debugf("session is closed")
	}
}

func (s *Session) Keepalive(interval, timeout time.Duration, retries int) {
	if interval <= 0 {
		interval = defaultKeepaliveInterval
	}
	if timeout <= 0 {
		timeout = defaultKeepaliveTimeout
	}
	if retries <= 0 {
		retries = defaultkeepaliveRetries
	}

	s.log.Debugf("keepalive is enabled, interval: %v, timeout: %v, retries: %d", interval, timeout, retries)
	defer close(s.dead)

	t := time.NewTicker(interval)
	defer t.Stop()

	count := retries
	for {
		select {
		case <-t.C:
			start := time.Now()
			err := func() error {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()

				select {
				case err := <-s.ping():
					return err
				case <-ctx.Done():
					return ctx.Err()
				}
			}()
			if err != nil {
				s.log.Debugf("ssh ping: %v", err)
				count--
				if count == 0 {
					return
				}
				continue
			}
			s.log.Debugf("ssh ping OK, RTT: %v", time.Since(start))
			count = retries
		case <-s.closed:
			return
		}
	}
}

func (s *Session) ping() <-chan error {
	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		if _, _, err := s.client.SendRequest("ping", true, nil); err != nil {
			ch <- err
		}
	}()
	return ch
}
