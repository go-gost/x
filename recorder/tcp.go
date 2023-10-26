package recorder

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/core/recorder"
)

type tcpRecorderOptions struct {
	timeout time.Duration
}

type TCPRecorderOption func(opts *tcpRecorderOptions)

func TimeoutTCPRecorderOption(timeout time.Duration) TCPRecorderOption {
	return func(opts *tcpRecorderOptions) {
		opts.timeout = timeout
	}
}

type tcpRecorder struct {
	addr   string
	dialer *net.Dialer
}

// TCPRecorder records data to TCP service.
func TCPRecorder(addr string, opts ...TCPRecorderOption) recorder.Recorder {
	var options tcpRecorderOptions
	for _, opt := range opts {
		opt(&options)
	}

	return &tcpRecorder{
		addr: addr,
		dialer: &net.Dialer{
			Timeout: options.timeout,
		},
	}
}

func (r *tcpRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	c, err := r.dialer.DialContext(ctx, "tcp", r.addr)
	if err != nil {
		return err
	}
	defer c.Close()

	_, err = c.Write(b)
	return err
}
