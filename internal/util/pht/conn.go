package pht

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/go-gost/core/logger"
)

type clientConn struct {
	client     *http.Client
	pushURL    string
	pullURL    string
	buf        []byte
	rxc        chan []byte
	closed     chan struct{}
	mu         sync.Mutex
	localAddr  net.Addr
	remoteAddr net.Addr
	logger     logger.Logger
}

func (c *clientConn) Read(b []byte) (n int, err error) {
	if len(c.buf) == 0 {
		select {
		case c.buf = <-c.rxc:
		case <-c.closed:
			err = io.ErrClosedPipe
			return
		}
	}

	n = copy(b, c.buf)
	c.buf = c.buf[n:]

	return
}

func (c *clientConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return
	}
	return c.write(b)
}

func (c *clientConn) write(b []byte) (n int, err error) {
	if c.isClosed() {
		err = io.ErrClosedPipe
		return
	}

	var r io.Reader
	if len(b) > 0 {
		buf := bytes.NewBufferString(base64.StdEncoding.EncodeToString(b))
		buf.WriteByte('\n')
		r = buf
	}

	req, err := http.NewRequest(http.MethodPost, c.pushURL, r)
	if err != nil {
		return
	}

	if c.logger.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpRequest(req, false)
		c.logger.Trace(string(dump))
	} else if c.logger.IsLevelEnabled(logger.DebugLevel) {
		c.logger.Debugf("%s %s", req.Method, req.URL)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if c.logger.IsLevelEnabled(logger.TraceLevel) {
		dump, _ := httputil.DumpResponse(resp, false)
		c.logger.Trace(string(dump))
	}

	if resp.StatusCode != http.StatusOK {
		err = errors.New(resp.Status)
		return
	}

	n = len(b)
	return
}

func (c *clientConn) readLoop() {
	for {
		if c.isClosed() {
			return
		}

		done := true
		err := func() error {
			r, err := http.NewRequest(http.MethodGet, c.pullURL, nil)
			if err != nil {
				return err
			}

			if c.logger.IsLevelEnabled(logger.TraceLevel) {
				dump, _ := httputil.DumpRequest(r, false)
				c.logger.Trace(string(dump))
			} else if c.logger.IsLevelEnabled(logger.DebugLevel) {
				c.logger.Debugf("%s %s", r.Method, r.URL)
			}

			resp, err := c.client.Do(r)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if c.logger.IsLevelEnabled(logger.TraceLevel) {
				dump, _ := httputil.DumpResponse(resp, false)
				c.logger.Trace(string(dump))
			}

			if resp.StatusCode != http.StatusOK {
				return errors.New(resp.Status)
			}

			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				done = false
				if scanner.Text() == "" {
					continue
				}

				b, err := base64.StdEncoding.DecodeString(scanner.Text())
				if err != nil {
					return err
				}
				select {
				case c.rxc <- b:
				case <-c.closed:
					return net.ErrClosed
				}
			}
			return scanner.Err()
		}()

		if err != nil {
			c.Close()
			return
		}

		if done { // server connection closed
			return
		}
	}
}

func (c *clientConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *clientConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *clientConn) Close() error {
	c.mu.Lock()

	select {
	case <-c.closed:
		c.mu.Unlock()
		return nil
	default:
		close(c.closed)
	}

	c.mu.Unlock()

	_, err := c.write(nil)

	return err
}

func (c *clientConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return true
	default:
	}
	return false
}

func (c *clientConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *clientConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *clientConn) SetDeadline(t time.Time) error {
	return nil
}

type serverConn struct {
	net.Conn
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (c *serverConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *serverConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}
