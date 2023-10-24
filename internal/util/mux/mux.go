package mux

import (
	"net"
	"time"

	smux "github.com/xtaci/smux"
)

const (
	defaultVersion = 1
)

type Config struct {
	// SMUX Protocol version, support 1,2
	Version int

	// Disabled keepalive
	KeepAliveDisabled bool

	// KeepAliveInterval is how often to send a NOP command to the remote
	KeepAliveInterval time.Duration

	// KeepAliveTimeout is how long the session
	// will be closed if no data has arrived
	KeepAliveTimeout time.Duration

	// MaxFrameSize is used to control the maximum
	// frame size to sent to the remote
	MaxFrameSize int

	// MaxReceiveBuffer is used to control the maximum
	// number of data in the buffer pool
	MaxReceiveBuffer int

	// MaxStreamBuffer is used to control the maximum
	// number of data per stream
	MaxStreamBuffer int
}

func convertConfig(cfg *Config) *smux.Config {
	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = defaultVersion

	if cfg == nil {
		return smuxCfg
	}

	if cfg.Version > 0 {
		smuxCfg.Version = cfg.Version
	}
	smuxCfg.KeepAliveDisabled = cfg.KeepAliveDisabled
	if cfg.KeepAliveInterval > 0 {
		smuxCfg.KeepAliveInterval = cfg.KeepAliveInterval
	}
	if cfg.KeepAliveTimeout > 0 {
		smuxCfg.KeepAliveTimeout = cfg.KeepAliveTimeout
	}
	if cfg.MaxFrameSize > 0 {
		smuxCfg.MaxFrameSize = cfg.MaxFrameSize
	}
	if cfg.MaxReceiveBuffer > 0 {
		smuxCfg.MaxReceiveBuffer = cfg.MaxReceiveBuffer
	}
	if cfg.MaxStreamBuffer > 0 {
		smuxCfg.MaxStreamBuffer = cfg.MaxStreamBuffer
	}

	return smuxCfg
}

type Session struct {
	conn    net.Conn
	session *smux.Session
}

func ClientSession(conn net.Conn, cfg *Config) (*Session, error) {
	s, err := smux.Client(conn, convertConfig(cfg))
	if err != nil {
		return nil, err
	}
	return &Session{
		conn:    conn,
		session: s,
	}, nil
}

func ServerSession(conn net.Conn, cfg *Config) (*Session, error) {
	s, err := smux.Server(conn, convertConfig(cfg))
	if err != nil {
		return nil, err
	}
	return &Session{
		conn:    conn,
		session: s,
	}, nil
}

func (session *Session) GetConn() (net.Conn, error) {
	stream, err := session.session.OpenStream()
	if err != nil {
		return nil, err
	}
	return &streamConn{Conn: session.conn, stream: stream}, nil
}

func (session *Session) Accept() (net.Conn, error) {
	stream, err := session.session.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &streamConn{Conn: session.conn, stream: stream}, nil
}

func (session *Session) Close() error {
	if session.session == nil {
		return nil
	}
	return session.session.Close()
}

func (session *Session) IsClosed() bool {
	if session.session == nil {
		return true
	}
	return session.session.IsClosed()
}

func (session *Session) NumStreams() int {
	return session.session.NumStreams()
}

type streamConn struct {
	net.Conn
	stream *smux.Stream
}

func (c *streamConn) Read(b []byte) (n int, err error) {
	return c.stream.Read(b)
}

func (c *streamConn) Write(b []byte) (n int, err error) {
	return c.stream.Write(b)
}

func (c *streamConn) Close() error {
	return c.stream.Close()
}
