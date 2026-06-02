package tunnel

import (
	"context"
	"net"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/sd"
)

// Dialer resolves a tunnel connector and returns a stream to it.
//
// Dial strategy (two-phase):
//  1. Local pool: try ConnectorPool.Get() up to retry times. Each attempt
//     calls GetConn() (= mux.OpenStream) on the same connector — if the
//     connector is dead, all retries fail until Tunnel.clean() removes it
//     (up to TTL, default 15s).
//  2. SD fallback: if pool returns nil AND sd is configured, query service
//     discovery for remote nodes. Filter out self (d.Node) and mismatched
//     networks. Establish a raw TCP connection to the remote address,
//     bypassing the mux layer entirely.
//
// The returned node and connector ID identify which node/hop the stream
// is connected to — used by callers to decide the relay protocol framing.
type Dialer struct {
	Node    string
	Pool    *ConnectorPool
	SD      sd.SD
	Retry   int
	Timeout time.Duration
	Log     logger.Logger
}

func (d *Dialer) Dial(ctx context.Context, network string, tid string) (conn net.Conn, node string, cid string, err error) {
	retry := d.Retry
	if retry <= 0 {
		retry = 1
	}

	for i := 0; i < retry; i++ {
		c := d.Pool.Get(network, tid)
		if c == nil {
			err = nil // clear stale err so SD fallback is not masked
			break
		}

		conn, err = c.GetConn()
		if err != nil {
			d.Log.Error(err)
			continue
		}
		node = d.Node
		cid = c.id.String()

		break
	}
	if conn != nil || err != nil {
		return
	}

	if d.SD == nil {
		err = ErrTunnelNotAvailable
		return
	}

	ss, err := d.SD.Get(ctx, tid)
	if err != nil {
		return
	}

	var service *sd.Service
	for _, s := range ss {
		d.Log.Debugf("%+v", s)
		if s.Node != d.Node && s.Network == network {
			service = s
			break
		}
	}
	if service == nil || service.Address == "" {
		err = ErrTunnelNotAvailable
		return
	}

	node = service.Node
	cid = service.ID

	dialer := net.Dialer{
		Timeout: d.Timeout,
	}
	conn, err = dialer.DialContext(ctx, "tcp", service.Address)
	return
}